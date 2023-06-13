package com.dpforge.dns.client.message

import java.net.InetAddress

class ResourceRecord(
    val name: String,
    val type: Type,
    val clazz: Class,
    val ttl: Long, // seconds
    val data: Data
) {

    enum class Type(val value: Short) {
        A(1), // a host address
        NS(2), // an authoritative name server
        MD(3), // a mail destination (Obsolete - use MX)
        MF(4), // a mail forwarder (Obsolete - use MX)
        CNAME(5), // the canonical name for an alias
        SOA(6), // marks the start of a zone of authority
        MB(7), // a mailbox domain name (EXPERIMENTAL)
        MG(8), // a mail group member (EXPERIMENTAL)
        MR(9), // a mail rename domain name (EXPERIMENTAL)
        NULL(10), // a null RR (EXPERIMENTAL)
        WKS(11), // a well known service description
        PTR(12), // a domain name pointer
        HINFO(13), // host information
        MINFO(14), // mailbox or mail list information
        MX(15), // mail exchange
        TXT(16), // text strings

        // Additional RFCs
        AAAA(28), // IPv6 address record (RFC 3596)
        SRV(33), // Service locator (RFC 2782)
        HTTPS(65), // HTTPS Binding (IETF Draft)
        CAA(257), // Certification Authority Authorization (RFC 6844)

        // QType
        AXFR(252), // A request for a transfer of an entire zone
        MAILB(253), // A request for mailbox-related records (MB, MG or MR)
        MAILA(254), // A request for mail agent RRs (Obsolete - see MX)
        ALL(255), // A request for all records
        ;

        companion object {
            fun getByValue(value: Short): Type = values().find { it.value == value } ?: error("Bad Type: $value")
        }
    }

    enum class Class(val value: Short) {
        IN(1), // the Internet
        CS(2), // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH(3), // the CHAOS class
        HS(4), // Hesiod [Dyer 87]

        // QClass
        ANY(255); // any class

        companion object {
            fun getByValue(value: Short): Class = values().find { it.value == value } ?: error("Bad Class: $value")
        }
    }

    sealed class Data {
        class A(rawIP: ByteArray) : Data() {
            /**
             * A 32 bit Internet address
             */
            val ip: InetAddress = InetAddress.getByAddress(rawIP)
        }

        /**
         * NS records cause both the usual additional section processing to locate
         * a type A record, and, when used in a referral, a special search of the
         * zone in which they reside for glue information.
         */
        class NS(
            /**
             * A domain name which specifies a host which should be authoritative for the specified class and domain.
             */
            val name: String
        ) : Data()

        /**
         * OBSOLETE
         */
        class MD(
            /**
             * A domain name which specifies a host which has a mail agent for the domain which should be able
             * to deliver mail for the domain.
             */
            val name: String
        ) : Data()

        /**
         * OBSOLETE
         */
        class MF(
            /**
             * A domain name which specifies a host which has a mail agent for the domain which will accept mail for
             * forwarding to the domain.
             */
            val name: String
        ) : Data()

        class CNAME(
            /**
             * A domain name which specifies the canonical or primary name for the owner. The owner name is an alias.
             */
            val name: String
        ) : Data()

        class SOA(
            val dataSourceDomainName: String,
            val mailboxDomainName: String,
            val serial: Long,
            val refresh: Long,
            val retry: Long,
            val expire: Long,
            val minimum: Long
        ) : Data()

        /**
         * EXPERIMENTAL
         */
        class MB(
            /**
             * A domain name which specifies a host which has the specified mailbox.
             */
            val name: String
        ) : Data()

        /**
         * EXPERIMENTAL
         */
        class MG(
            /**
             * A domain name which specifies a mailbox which is a member of the mail group specified by the domain name.
             */
            val name: String
        ) : Data()

        /**
         * EXPERIMENTAL
         */
        class MR(
            /**
             * A domain name which specifies a mailbox which is the proper rename of the specified mailbox.
             */
            val name: String
        ) : Data()

        /**
         * EXPERIMENTAL
         */
        class NULL(
            val rawData: ByteArray
        ) : Data()

        class WKS(
            rawIP: ByteArray,
            /**
             * An 8 bit IP protocol number (RFC-1010)
             */
            val protocol: Int,
            /**
             * A variable length bit map (RFC-1010)
             */
            val bitMap: ByteArray
        ) : Data() {
            /**
             * A 32 bit Internet address
             */
            val ip: InetAddress = InetAddress.getByAddress(rawIP)
        }

        class PTR(
            /**
             * A domain name which points to some location in the domain name space
             */
            val name: String
        ) : Data()

        class HINFO(
            /**
             * A character string which specifies the CPU type.
             */
            val cpu: String,
            /**
             * A <character-string> which specifies the operating system type.
             */
            val os: String
        ) : Data()

        /**
         * EXPERIMENTAL
         */
        class MINFO(
            val rMailBox: String,
            val eMailBox: String
        ) : Data()

        class MX(val preference: Int, val exchange: String) : Data()

        class TXT(val texts: List<String>) : Data()

        class AAAA(rawIP: ByteArray) : Data() {
            val ip: InetAddress = InetAddress.getByAddress(rawIP)
        }

        class SRV(val priority: Int, val weight: Int, val port: Int, val target: String) : Data()

        class HTTPS(val svcPriority: Int, val targetName: String, val svcParams: List<Pair<Int, String>>) : Data()
        class CAA(val flags: Int, val tag: String, val value: ByteArray) : Data()
    }
}