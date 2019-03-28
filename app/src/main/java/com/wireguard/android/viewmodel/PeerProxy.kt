/*
 * Copyright © 2017-2018 WireGuard LLC.
 * Copyright © 2018-2019 Harsh Shandilya <msfjarvis@gmail.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.viewmodel

import android.os.Parcel
import android.os.Parcelable
import androidx.databinding.BaseObservable
import androidx.databinding.Observable
import androidx.databinding.ObservableBoolean
import androidx.databinding.ObservableField
import androidx.databinding.ObservableInt
import androidx.databinding.ObservableList
import com.wireguard.config.Attribute
import com.wireguard.config.BadConfigException
import com.wireguard.config.Peer
import java.lang.ref.WeakReference
import java.util.ArrayList
import java.util.LinkedHashSet

class PeerProxy : BaseObservable, Parcelable {

    private val dnsRoutes = ArrayList<String>()
    var allowedIps: ObservableField<String> = ObservableField()
        set(value) {
            field = value
            calculateAllowedIpsState()
        }
    private var allowedIpsState: ObservableField<AllowedIpsState> = ObservableField(AllowedIpsState.INVALID)
    var endpoint: ObservableField<String> = ObservableField()
    private var interfaceDnsListener: InterfaceDnsListener? = null
    private var owner: ConfigProxy? = null
    private var peerListListener: PeerListListener? = null
    var persistentKeepalive: ObservableField<String> = ObservableField()
    var preSharedKey: ObservableField<String> = ObservableField()
    var publicKey: ObservableField<String> = ObservableField()
    var totalPeers: ObservableInt = ObservableInt(0)
        set(value) {
            if (field == value)
                return
            field = value
            calculateAllowedIpsState()
        }

    private val allowedIpsSet: Set<String>
        get() = LinkedHashSet(Attribute.split(allowedIps.toString()).toSet())

    val isAbleToExcludePrivateIps: ObservableBoolean
        get() {
            return ObservableBoolean(
                allowedIpsState == AllowedIpsState.CONTAINS_IPV4_PUBLIC_NETWORKS ||
                    allowedIpsState == AllowedIpsState.CONTAINS_IPV4_WILDCARD
            )
        }

    // Replace the first instance of the wildcard with the public network list, or vice versa.
    // DNS servers only need to handled specially when we're excluding private IPs.
    var isExcludingPrivateIps: ObservableBoolean
        get() = ObservableBoolean(allowedIpsState == AllowedIpsState.CONTAINS_IPV4_PUBLIC_NETWORKS)
        set(excludingPrivateIps) {
            val excludingPrivateIpsBool = excludingPrivateIps.get()
            if (!isAbleToExcludePrivateIps.get() || isExcludingPrivateIps == excludingPrivateIps)
                return
            val oldNetworks = if (excludingPrivateIpsBool) IPV4_WILDCARD else IPV4_PUBLIC_NETWORKS
            val newNetworks = if (excludingPrivateIpsBool) IPV4_PUBLIC_NETWORKS else IPV4_WILDCARD
            val input = allowedIpsSet
            val outputSize = input.size - oldNetworks.size + newNetworks.size
            val output = LinkedHashSet<String>(outputSize)
            var replaced = false
            for (network in input) {
                if (oldNetworks.contains(network)) {
                    if (!replaced) {
                        for (replacement in newNetworks)
                            if (!output.contains(replacement))
                                output.add(replacement)
                        replaced = true
                    }
                } else if (!output.contains(network)) {
                    output.add(network)
                }
            }
            if (excludingPrivateIpsBool)
                output.addAll(dnsRoutes)
            else
                output.removeAll(dnsRoutes)
            allowedIps.set(Attribute.join(output))
            allowedIpsState.set(
                if (excludingPrivateIpsBool)
                    AllowedIpsState.CONTAINS_IPV4_PUBLIC_NETWORKS
                else
                    AllowedIpsState.CONTAINS_IPV4_WILDCARD
            )
        }

    fun toggleExcludePrivateIPs() {
        isExcludingPrivateIps.set(!isExcludingPrivateIps.get())
    }

    private constructor(`in`: Parcel) {
        allowedIps.set(`in`.readString())
        endpoint.set(`in`.readString())
        persistentKeepalive.set(`in`.readString())
        preSharedKey.set(`in`.readString())
        publicKey.set(`in`.readString())
    }

    constructor(other: Peer) {
        allowedIps.set(Attribute.join(other.allowedIps))
        endpoint.set(other.endpoint?.toString())
        persistentKeepalive.set(other.persistentKeepalive?.toString())
        preSharedKey.set(other.preSharedKey?.toBase64())
        publicKey.set(other.publicKey.toBase64())
    }

    constructor() {
        allowedIps.set("")
        endpoint.set("")
        persistentKeepalive.set("")
        preSharedKey.set("")
        publicKey.set("")
    }

    fun bind(owner: ConfigProxy) {
        val interfaze = owner.`interface`
        val peers = owner.peers
        if (interfaceDnsListener == null)
            interfaceDnsListener = InterfaceDnsListener(this)
        interfaze.addOnPropertyChangedCallback(interfaceDnsListener!!)
        setInterfaceDns(interfaze.dnsServers.get())
        if (peerListListener == null)
            peerListListener = PeerListListener(this)
        peers.addOnListChangedCallback(peerListListener)
        totalPeers.set(peers.size)
        this.owner = owner
    }

    private fun calculateAllowedIpsState() {
        val newState: AllowedIpsState
        newState = if (totalPeers.get() == 1) {
            // String comparison works because we only care if allowedIps is a superset of one of
            // the above sets of (valid) *networks*. We are not checking for a superset based on
            // the individual addresses in each set.
            val networkStrings = allowedIpsSet
            // If allowedIps contains both the wildcard and the public networks, then private
            // networks aren't excluded!
            when {
                networkStrings.containsAll(IPV4_WILDCARD) -> AllowedIpsState.CONTAINS_IPV4_WILDCARD
                networkStrings.containsAll(IPV4_PUBLIC_NETWORKS) -> AllowedIpsState.CONTAINS_IPV4_PUBLIC_NETWORKS
                else -> AllowedIpsState.OTHER
            }
        } else {
            AllowedIpsState.INVALID
        }
        if (newState != allowedIpsState) {
            allowedIpsState.set(newState)
        }
    }

    override fun describeContents(): Int {
        return 0
    }

    @Throws(BadConfigException::class)
    fun resolve(): Peer {
        val builder = Peer.Builder()
        allowedIps.get()?.let { if (it.isNotEmpty()) builder.parseAllowedIPs(it) }
        endpoint.get()?.let { if (it.isNotEmpty()) builder.parseEndpoint(it) }
        persistentKeepalive.get()?.let { if (it.isNotEmpty()) builder.parsePersistentKeepalive(it) }
        preSharedKey.get()?.let { if (it.isNotEmpty()) builder.parsePreSharedKey(it) }
        publicKey.get()?.let { if (it.isNotEmpty()) builder.parsePublicKey(it) }
        return builder.build()
    }

    private fun setInterfaceDns(dnsServers: CharSequence?) {
        val newDnsRoutes: Array<String> = Attribute.split(dnsServers ?: "")
            .filter { server -> !server.contains(":") }
            .map { server -> "$server/32" }
            .toTypedArray()
        if (allowedIpsState == AllowedIpsState.CONTAINS_IPV4_PUBLIC_NETWORKS) {
            val input = allowedIpsSet
            val output = LinkedHashSet<String>(input.size + 1)
            // Yes, this is quadratic in the number of DNS servers, but most users have 1 or 2.
            for (network in input)
                if (!dnsRoutes.contains(network) || newDnsRoutes.contains(network))
                    output.add(network)
            // Since output is a Set, this does the Right Thing™ (it does not duplicate networks).
            output.addAll(newDnsRoutes)
            // None of the public networks are /32s, so this cannot change the AllowedIPs state.
            allowedIps.set(Attribute.join(output))
        }
        dnsRoutes.clear()
        dnsRoutes.addAll(newDnsRoutes)
    }

    fun unbind() {
        if (owner == null)
            return
        owner?.let {
            val interfaze = it.`interface`
            val peers = it.peers
            interfaceDnsListener?.let { interfaceDnsListener ->
                interfaze.removeOnPropertyChangedCallback(
                    interfaceDnsListener
                )
            }
            peerListListener?.let { peerListListener -> peers.removeOnListChangedCallback(peerListListener) }
            peers.remove(this)
            setInterfaceDns("")
            totalPeers.set(0)
        }
        owner = null
    }

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeString(allowedIps.get())
        dest.writeString(endpoint.get())
        dest.writeString(persistentKeepalive.get())
        dest.writeString(preSharedKey.get())
        dest.writeString(publicKey.get())
    }

    private enum class AllowedIpsState {
        CONTAINS_IPV4_PUBLIC_NETWORKS,
        CONTAINS_IPV4_WILDCARD,
        INVALID,
        OTHER
    }

    private class InterfaceDnsListener(peerProxy: PeerProxy) :
        Observable.OnPropertyChangedCallback() {
        private val weakPeerProxy: WeakReference<PeerProxy> = WeakReference(peerProxy)

        override fun onPropertyChanged(sender: Observable, propertyId: Int) {
            val peerProxy: PeerProxy? = weakPeerProxy.get()
            if (peerProxy == null) {
                sender.removeOnPropertyChangedCallback(this)
                return
            }
            // This shouldn't be possible, but try to avoid a ClassCastException anyway.
            if (sender !is InterfaceProxy)
                return
            peerProxy.setInterfaceDns(sender.dnsServers.get())
        }
    }

    private class PeerListListener(peerProxy: PeerProxy) :
        ObservableList.OnListChangedCallback<ObservableList<PeerProxy>>() {
        private val weakPeerProxy: WeakReference<PeerProxy> = WeakReference(peerProxy)

        override fun onChanged(sender: ObservableList<PeerProxy>) {
            val peerProxy: PeerProxy? = weakPeerProxy.get()
            if (peerProxy == null) {
                sender.removeOnListChangedCallback(this)
                return
            }
            peerProxy.totalPeers.set(sender.size)
        }

        override fun onItemRangeChanged(
            sender: ObservableList<PeerProxy>,
            positionStart: Int,
            itemCount: Int
        ) {
            // Do nothing.
        }

        override fun onItemRangeInserted(
            sender: ObservableList<PeerProxy>,
            positionStart: Int,
            itemCount: Int
        ) {
            onChanged(sender)
        }

        override fun onItemRangeMoved(
            sender: ObservableList<PeerProxy>,
            fromPosition: Int,
            toPosition: Int,
            itemCount: Int
        ) {
            // Do nothing.
        }

        override fun onItemRangeRemoved(
            sender: ObservableList<PeerProxy>,
            positionStart: Int,
            itemCount: Int
        ) {
            onChanged(sender)
        }
    }

    private class PeerProxyCreator : Parcelable.Creator<PeerProxy> {
        override fun createFromParcel(`in`: Parcel): PeerProxy {
            return PeerProxy(`in`)
        }

        override fun newArray(size: Int): Array<PeerProxy?> {
            return arrayOfNulls(size)
        }
    }

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<PeerProxy> = PeerProxyCreator()
        private val IPV4_PUBLIC_NETWORKS = LinkedHashSet(
            listOf(
                "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3",
                "64.0.0.0/2", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12",
                "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7",
                "176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16",
                "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12", "192.192.0.0/10",
                "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4"
            )
        )
        private val IPV4_WILDCARD = setOf("0.0.0.0/0")
    }
}
