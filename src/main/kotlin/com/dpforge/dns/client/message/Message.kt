package com.dpforge.dns.client.message

class Message(
    val id: Short,  // ID
    val qr: QR, // QR
    val opcode: Opcode, // OPCODE
    val authoritativeAnswer: Boolean = false, // AA
    val truncation: Boolean = false, // TrunCation,
    val recursionDesired: Boolean = false, // RD
    val recursionAvailable: Boolean = false, // RA
    val responseCode: ResponseCode = ResponseCode.NO_ERROR, // RCODE
    val questions: List<Question> = emptyList(),
    val answers: List<ResourceRecord> = emptyList(),
    val nameServers: List<ResourceRecord> = emptyList(),
    val additionalRecords: List<ResourceRecord> = emptyList(),
) {
    // order matters
    enum class QR {
        QUERY,
        RESPONSE
    }

    // order matters
    enum class Opcode {
        STANDARD_QUERY, // QUERY
        INVERSE_QUERY, // IQUERY
        SERVER_STATUS_REQUEST, // STATUS
    }

    // order matters
    enum class ResponseCode {
        /**
         * No error condition
         */
        NO_ERROR,

        /**
         * The name server was unable to interpret the query
         */
        FORMAT_ERROR,

        /**
         * The name server was unable to process this query due to a problem with the name server
         */
        SERVER_FAILURE,

        /**
         * Meaningful only for responses from an authoritative name server, this code signifies that
         * the domain name referenced in the query does not exist
         */
        NAME_ERROR,

        /**
         * The name server does not support the requested kind of query
         */
        NOT_IMPLEMENTED,

        /**
         * The name server refuses to perform the specified operation for policy reasons.  For example, a name
         * server may not wish to provide the information to the particular requester, or a name server
         * may not wish to perform a particular operation (e.g., zone transfer) for particular data.
         */
        REFUSED,
    }
}