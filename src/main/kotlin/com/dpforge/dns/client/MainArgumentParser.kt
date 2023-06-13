package com.dpforge.dns.client

import com.dpforge.dns.client.message.ResourceRecord

object MainArgumentParser {

    fun parseArguments(args: Array<String>): Resolver.Arguments {
        if (args.isEmpty()) {
            throw ParseException("No domain name provided")
        }
        var rootServer: Resolver.RootServer? = null
        var type: ResourceRecord.Type? = null
        var i = 0
        while (i < args.size - 1) {
            when (args[i].trim().lowercase()) {
                "-s" -> rootServer = parseRootServer(args.getOrNull(++i))
                "-t" -> type = parseType(args.getOrNull(++i))
                else -> throw ParseException("Unknown argument: ${args[i]}")
            }
            i++
        }
        return Resolver.Arguments(
            domainName = args.last(),
            type = type ?: ResourceRecord.Type.A,
            clazz = ResourceRecord.Class.IN,
            rootServer = rootServer
        )
    }

    private fun parseType(value: String?): ResourceRecord.Type {
        if (value == null) {
            throw ParseException("Type is not provided")
        }
        try {
            return ResourceRecord.Type.valueOf(value.trim().uppercase())
        } catch (e: IllegalArgumentException) {
            throw ParseException("Unknown type: $value")
        }
    }

    private fun parseRootServer(value: String?): Resolver.RootServer {
        if (value == null) {
            throw ParseException("Root server is not provided")
        }
        @Suppress("NAME_SHADOWING")
        val value = value.trim().lowercase()
        if (value.length == 1) {
            return Resolver.ROOT_SERVERS.find { it.hostname.startsWith(value) }
                ?: throw ParseException("Unknown root server: $value")
        }
        if (value.split(".").mapNotNull { it.toIntOrNull() }.size != 4) {
            throw ParseException("Bad IPv4 address: $value")
        }
        return Resolver.RootServer(ipAddressV4 = value, hostname = "")
    }

    class ParseException(message: String) : Exception(message)
}
