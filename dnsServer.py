import socket, glob, json

class DnsServer:
    def __init__(self):
        # Use DNS default port
        self.port = 53

        # Set the IP
        ipAdresses = socket.gethostbyname_ex(socket.gethostname())[-1]

        print("Select your IP Address:")
        for i in range(0, len(ipAdresses)):
            print(str(i + 1) + ".", ipAdresses[i])

        selected = input("Enter the IP index >> ")
        self.ip = ipAdresses[int(selected) - 1]

        # Zone data load
        self.zoneData = self.loadZones()

        # Instance socket object
        # AF_INET: use IPv4
        # SOCK_DGRAM: use UDP
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind the socket
        self.serverSocket.bind((self.ip, self.port))

        print("Server initialized.")

    def loadZones(self):
        """
        Load all DNS zones
        """
        self.zoneData = {}
        zoneFiles = glob.glob('zones/*.zone')

        for zone in zoneFiles:
            with open(zone) as zoneData:
                data = json.load(zoneData)
                zoneName = data["$origin"]
                self.zoneData[zoneName] = data
        
        return self.zoneData

    def getFlags(self, request: bytes):
        """
        Get the flags from an original DNS request.
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        where:
        QR              A one bit field that specifies whether this message is a
                        query (0), or a response (1).

        OPCODE          A four bit field that specifies kind of query in this
                        message.  This value is set by the originator of a query
                        and copied into the response.  The values are:

                        0               a standard query (QUERY)

                        1               an inverse query (IQUERY)

                        2               a server status request (STATUS)

                        3-15            reserved for future use

        AA              Authoritative Answer - this bit is valid in responses,
                        and specifies that the responding name server is an
                        authority for the domain name in question section.

                        Note that the contents of the answer section may have
                        multiple owner names because of aliases.  The AA bit
                        corresponds to the name which matches the query name, or
                        the first owner name in the answer section.

        TC              TrunCation - specifies that this message was truncated
                        due to length greater than that permitted on the
                        transmission channel.

        RD              Recursion Desired - this bit may be set in a query and
                        is copied into the response.  If RD is set, it directs
                        the name server to pursue the query recursively.
                        Recursive query support is optional.

        RA              Recursion Available - this be is set or cleared in a
                        response, and denotes whether recursive query support is
                        available in the name server.

        Z               Reserved for future use.  Must be zero in all queries
                        and responses.

        RCODE           Response code - this 4 bit field is set as part of
                        responses.  The values have the following
                        interpretation:

                        0               No error condition

                        1               Format error - The name server was
                                        unable to interpret the query.

                        2               Server failure - The name server was
                                        unable to process this query due to a
                                        problem with the name server.

                        3               Name Error - Meaningful only for
                                        responses from an authoritative name
                                        server, this code signifies that the
                                        domain name referenced in the query does
                                        not exist.

                        4               Not Implemented - The name server does
                                        not support the requested kind of query.

                        5               Refused - The name server refuses to
                                        perform the specified operation for
                                        policy reasons.  For example, a name
                                        server may not wish to provide the
                                        information to the particular requester,
                                        or a name server may not wish to perform
                                        a particular operation (e.g., zone
                                        transfer) for particular data.

                        6-15            Reserved for future use.
        """
        # Get specific part of the request
        request = request[2:4]

        # Get data from the request
        REQUEST_BYTE_1 = bytes(request[:1])
        REQUEST_BYTE_2 = bytes(request[1:2])

        # Create the string that stores the response flags
        responseFlags = ''

        # QR is 1 because it is a response
        QR = '1'

        # Get the opcode from the request
        opcode = ''
        for bit in range(1, 5):
            # Convert first byte to integer and get every bit at a specific position
            opcode += str(ord(REQUEST_BYTE_1) & (1 << bit))
        
        # The authorative answer will always be 1
        AA = '1'

        # The message is never truncated assuming the messages are short
        TC = '0'

        # Recursion and errors will not be supported for this project
        RD = '0'
        RA = '0'
        RCODE = '0000'

        # As stated above, Z must always be zero
        Z = '000'

        return int(QR+opcode+AA+TC+RD, 2).to_bytes(1, byteorder='big') +\
            int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

    def getQuestionDomain(self, request: bytes):
        """
        This method extracts the domain name and question type from the DNS request.
        """
        # Define the variables
        state = 0
        expectedLenght = 0
        domainString = ''
        domainParts = []
        x = 0
        y = 0

        # For every byte in the request
        for byte in request:
            # If a new byte should be read
            if state == 1:
                # If the domain name is not read completely
                if byte != 0:
                    domainString += chr(byte)
                else:
                    domainParts.append(domainString)
                    break
                x += 1
                # If the byte reading is complete
                if x == expectedLenght:
                    domainParts.append(domainString)
                    # Reset variables
                    domainString = ''
                    state = 0
                    x = 0
            # If a new part from the domain should be read
            else:
                state = 1
                expectedLenght = byte
            
            y += 1

        # Get the question type which is after the domain name
        questionType = request[y:y+2]

        return (domainParts, questionType)

    def getZone(self, domain):
        zoneName = '.'.join(domain)
        return self.zoneData[zoneName]

    def getRecords(self, request: bytes):
        domain, questionType = self.getQuestionDomain(request)
        qt = ''

        if questionType == b'\x00\x01':
            qt = 'a'
            zone = self.getZone(domain)
            return (zone[qt], qt, domain)
        else:
            return (None, 'o', None)

    def recordToBytes(self, domainName: str, recordType: str, recordTtl: str, recordValue: str):
        """
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                      NAME                     /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     CLASS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TTL                      |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   RDLENGTH                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        /                     RDATA                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        where:

        NAME            a domain name to which this resource record pertains.

        TYPE            two octets containing one of the RR type codes.  This
                        field specifies the meaning of the data in the RDATA
                        field.

        CLASS           two octets which specify the class of the data in the
                        RDATA field.

        TTL             a 32 bit unsigned integer that specifies the time
                        interval (in seconds) that the resource record may be
                        cached before it should be discarded.  Zero values are
                        interpreted to mean that the RR can only be used for the
                        transaction in progress, and should not be cached.

        RDLENGTH        an unsigned 16 bit integer that specifies the length in
                        octets of the RDATA field.

        RDATA           a variable length string of octets that describes the
                        resource.  The format of this information varies
                        according to the TYPE and CLASS of the resource record.
                        For example, the if the TYPE is A and the CLASS is IN,
                        the RDATA field is a 4 octet ARPA Internet address.
        """
        recordBytes = b'\xc0\x0c'

        if recordType == 'a':
            recordBytes += bytes([0]) + bytes([1])
        
        recordBytes += bytes([0]) + bytes([1])

        recordBytes += int(recordTtl).to_bytes(4, byteorder='big')

        if recordType == 'a':
            recordBytes += bytes([0]) + bytes([4])

            for part in recordValue.split('.'):
                recordBytes += bytes([int(part)])
        
        return recordBytes

    def buildQuestion(self, domainName: str, recordType: str):
        questionBytes = b''
        for part in domainName:
            lenght = len(part)
            questionBytes += bytes([lenght])

            for char in part:
                questionBytes += ord(char).to_bytes(1, byteorder='big')
        
        if recordType == 'a':
                questionBytes += (1).to_bytes(2, byteorder='big')

        questionBytes += (1).to_bytes(2, byteorder='big')

        return questionBytes

    def getAnswerCount(self, request: bytes):
        return len(self.getRecords(request[12:])[0]).to_bytes(2, byteorder='big')

    def buildHeader(self, request: bytes):
        """
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     FLAGS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        # Get the transaction ID from the request
        ID = request[:2]

        # Get the flags from the request
        FLAGS = self.getFlags(request)

        # Question count (which is always one)
        QDCOUNT = b'\x00\x01'

        # Get answer count based on the records in the zone file
        ANCOUNT = self.getAnswerCount(request)

        # Nameserver count
        NSCOUNT = (0).to_bytes(2, byteorder='big')

        # Aditional count
        ARCOUNT = (0).to_bytes(2, byteorder='big')

        return ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT        

    def buildResponse(self, request: bytes):
        # Get DNS header
        dnsHeader = self.buildHeader(request)
        
        # Create DNS body
        dnsBody = b''

        # Get answer for the query
        records, recordType, domainName = self.getRecords(request[12:])
        dnsQuestion = self.buildQuestion(domainName, recordType)

        for record in records:
            dnsBody += self.recordToBytes(domainName, recordType, record["ttl"], record["value"])

        return dnsHeader + dnsQuestion + dnsBody

    def run(self):
        # Main method (program loop)
        while True:
            # Recieve 512 octects (bytes) as stated in the DNS standards
            data, addr = self.serverSocket.recvfrom(512)

            print("New DNS request recieved.")

            try:
                # Build DNS response
                response = self.buildResponse(data)

                # Respond
                self.serverSocket.sendto(response, addr)

                print("DNS request responded.")
            except Exception as exception:
                print("DNS address not found:", exception)
