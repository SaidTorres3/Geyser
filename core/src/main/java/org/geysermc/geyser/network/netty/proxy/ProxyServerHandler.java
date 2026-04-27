/*
 * Copyright (c) 2019-2023 GeyserMC. http://geysermc.org
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author GeyserMC
 * @link https://github.com/GeyserMC/Geyser
 */

package org.geysermc.geyser.network.netty.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import io.netty.handler.codec.haproxy.HAProxyProtocolException;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.geysermc.geyser.GeyserImpl;

import java.net.InetSocketAddress;

@ChannelHandler.Sharable
public class ProxyServerHandler extends SimpleChannelInboundHandler<DatagramPacket> {
    private static final InternalLogger log = InternalLoggerFactory.getInstance(ProxyServerHandler.class);
    public static final String NAME = "rak-proxy-server-handler";

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
        ByteBuf content = packet.content();

        // Since FRP 0.67.0, the PROXY protocol header is only sent on the first packet of each session.
        // Check the cache first: if we already have a real address for this sender, this is a subsequent
        // data packet with no header — forward it directly without running the PROXY detector.
        // This also avoids false-positive V1 detection, since ProxyProtocolDecoder.findVersion() returns 1
        // (V1 fallback) for any packet ≥13 bytes that lacks the V2 binary prefix, which includes all
        // ordinary RakNet packets.
        InetSocketAddress cachedAddress = GeyserImpl.getInstance().getGeyserServer().getProxiedAddresses().get(packet.sender());
        if (cachedAddress != null) {
            log.trace("Reusing PROXY session for proxy {}", packet.sender());
            ctx.fireChannelRead(packet.retain());
            return;
        }

        // No cached address — this must be the first packet, which should carry the PROXY header.
        int detectedVersion = ProxyProtocolDecoder.findVersion(content);
        if (detectedVersion == -1) {
            // Packet is too short to contain a PROXY header and we have no cached session.
            // Drop it.
            return;
        }

        final HAProxyMessage decoded;
        try {
            decoded = ProxyProtocolDecoder.decode(content, detectedVersion);
        } catch (HAProxyProtocolException e) {
            log.debug("{} sent malformed PROXY header", packet.sender(), e);
            return;
        }

        if (decoded == null) {
            // Not a valid PROXY header and no cached session — drop.
            return;
        }

        // Header decoded successfully. Cache the real address.
        InetSocketAddress realAddress = new InetSocketAddress(decoded.sourceAddress(), decoded.sourcePort());
        GeyserImpl.getInstance().getGeyserServer().getProxiedAddresses().put(packet.sender(), realAddress);
        log.debug("Got PROXY header: (from {}) {}", packet.sender(), realAddress);

        if (!content.isReadable()) {
            // Header-only packet (no RakNet payload). Address is cached; nothing to forward.
            return;
        }

        // Header + payload in the same datagram. Forward the remaining payload.
        ctx.fireChannelRead(packet.retain());
    }
}