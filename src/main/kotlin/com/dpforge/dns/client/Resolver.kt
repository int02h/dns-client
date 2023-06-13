package com.dpforge.dns.client

import com.dpforge.dns.client.message.Message
import com.dpforge.dns.client.message.MessageDecoder
import com.dpforge.dns.client.message.MessageEncoder
import com.dpforge.dns.client.message.Question
import com.dpforge.dns.client.message.ResourceRecord
import com.dpforge.dns.client.util.ByteArrayBuilder
import java.net.InetAddress
import java.net.Socket

/**
 * https://datatracker.ietf.org/doc/html/rfc1035
 */
class Resolver {

    fun resolve(args: Arguments): List<ResourceRecord> {
        val message = buildMessage(args)
        val rootServer = args.rootServer ?: ROOT_SERVERS.random()
        return resolveWith(message, InetAddress.getByName(rootServer.ipAddressV4))
    }

    private fun resolveWith(message: ByteArray, serverAddress: InetAddress): List<ResourceRecord> {
        val answer: ByteArray
        Socket(serverAddress, 53).use { clientSocket ->
            clientSocket.getOutputStream().use { output ->
                clientSocket.getInputStream().use { input ->
                    output.write(message)
                    output.flush()
                    val size = input.read().shl(8) + input.read()
                    answer = ByteArray(size)
                    input.read(answer)
                }
            }
        }
        val answerMessage = MessageDecoder().decode(answer)
        if (answerMessage.responseCode != Message.ResponseCode.NO_ERROR) {
            return emptyList()
        }
        if (answerMessage.answers.isNotEmpty()) {
            return answerMessage.answers
        } else {
            val addressMap = answerMessage.additionalRecords.filter { it.type == ResourceRecord.Type.A }
                .associate { it.name to (it.data as ResourceRecord.Data.A).ip }
            val nsRecords = answerMessage.nameServers.mapNotNull { it.data as? ResourceRecord.Data.NS }
            for (ns in nsRecords) {
                val ip = addressMap[ns.name]
                if (ip != null) {
                    return resolveWith(message, ip)
                }
                val result = resolve(
                    Arguments(
                        domainName = ns.name,
                        type = ResourceRecord.Type.A,
                        clazz = ResourceRecord.Class.IN,
                        rootServer = null
                    )
                )
                if (result.isNotEmpty()) {
                    return resolveWith(message, (result.first().data as ResourceRecord.Data.A).ip)
                }
            }
            return emptyList()
        }
    }

    private fun buildMessage(args: Arguments): ByteArray {
        val message = Message(
            id = 12354,
            qr = Message.QR.QUERY,
            opcode = Message.Opcode.STANDARD_QUERY,
            questions = listOf(
                Question(
                    name = args.domainName,
                    type = args.type,
                    clazz = args.clazz
                )
            )
        )
        val data = MessageEncoder().encode(message)
        return ByteArrayBuilder().addShort(data.size).addBytes(data).toByteArray()
    }

    class RootServer(val ipAddressV4: String, val hostname: String)

    class Arguments(
        val domainName: String,
        val type: ResourceRecord.Type,
        val clazz: ResourceRecord.Class,
        val rootServer: RootServer?
    )

    companion object {
        val ROOT_SERVERS = arrayOf(
            RootServer(ipAddressV4 = "198.41.0.4", hostname = "a.root-servers.net"),
            RootServer(ipAddressV4 = "199.9.14.201", hostname = "b.root-servers.net"),
            RootServer(ipAddressV4 = "192.33.4.12", hostname = "c.root-servers.net"),
            RootServer(ipAddressV4 = "199.7.91.13", hostname = "d.root-servers.net"),
            RootServer(ipAddressV4 = "192.203.230.10", hostname = "e.root-servers.net"),
            RootServer(ipAddressV4 = "192.5.5.241", hostname = "f.root-servers.net"),
            RootServer(ipAddressV4 = "192.112.36.4", hostname = "g.root-servers.net"),
            RootServer(ipAddressV4 = "198.97.190.53", hostname = "h.root-servers.net"),
            RootServer(ipAddressV4 = "192.36.148.17", hostname = "i.root-servers.net"),
            RootServer(ipAddressV4 = "192.58.128.30", hostname = "j.root-servers.net"),
            RootServer(ipAddressV4 = "193.0.14.129", hostname = "k.root-servers.net"),
            RootServer(ipAddressV4 = "199.7.83.42", hostname = "l.root-servers.net"),
            RootServer(ipAddressV4 = "202.12.27.33", hostname = "m.root-servers.net"),
        )
    }
}