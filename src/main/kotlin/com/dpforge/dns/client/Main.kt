package com.dpforge.dns.client

import com.dpforge.dns.client.message.ResourceRecord
import com.dpforge.dns.client.message.ResourceRecord.Data
import kotlin.system.exitProcess


fun main(args: Array<String>) {
    val resolverArgs: Resolver.Arguments
    try {
        resolverArgs = MainArgumentParser.parseArguments(args)
    } catch (e: MainArgumentParser.ParseException) {
        System.err.println(e.message)
        exitProcess(1)
    }
    val result = Resolver().resolve(resolverArgs)
    result.sortedBy { it.type.name }.forEach { printResourceRecord(it) }
}


private fun printResourceRecord(rr: ResourceRecord) {
    println(
        buildString {
            append(rr.name.padEnd(32))
            append(rr.type.toString().padEnd(8))
            append(rr.clazz.toString().padEnd(8))
            append(rr.data.asDisplayString())
        }
    )
}

private fun Data.asDisplayString(): String = when (this) {
    is Data.A -> ip.hostAddress
    is Data.AAAA -> ip.hostAddress
    is Data.CAA -> "$tag: ${value.toString(Charsets.US_ASCII)}"
    is Data.NS -> name
    is Data.TXT -> texts.joinToString(separator = " ") { "\"$it\"" }
    is Data.HTTPS -> "SvcPriority: $svcPriority; TargetName: $targetName; SvcParams: $svcParams"
    is Data.SOA -> "$dataSourceDomainName, $mailboxDomainName"
    is Data.MX -> exchange
    is Data.CNAME -> name
    is Data.PTR -> name
    is Data.SRV -> "$priority $weight $port $target"
    is Data.HINFO -> "\"$cpu\" \"$os\""
    is Data.MD -> name
    is Data.MF -> name
    is Data.MB -> name
    is Data.MG -> name
    is Data.MR -> name
    is Data.NULL -> "${rawData.size} bytes"
    is Data.WKS -> "${ip.hostAddress} $protocol"
    is Data.MINFO -> "$rMailBox, $eMailBox"
}

