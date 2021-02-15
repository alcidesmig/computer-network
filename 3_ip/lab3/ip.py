from iputils import *
from collections import defaultdict
from tcputils import *
import socket

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = defaultdict(lambda: {})
        self.cont = 0
    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        

        # datagrama = bytearray(datagrama)[:20]
        # datagrama[9:10] = b'\x00'
        # datagrama[9:10] = struct.pack('!B', ttl)
        # datagrama[10:12] = b'\x00\x00'
        # datagrama[10:12] = struct.pack('!H', calc_checksum(bytes(datagrama)))
        # datagrama = bytes(datagrama) + payload

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, \
                checksum, src_addr, dest_addr = struct.unpack('!BBHHHBBHII', datagrama[:20])
            ttl -= 1
            if ttl != 0:
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, \
                calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, \
                0, src_addr, dest_addr)), src_addr, dest_addr) + payload
                self.enlace.enviar(datagrama, next_hop)
            else:
                ttl = 64
                my_addr = int(struct.unpack('!I', str2addr(self.meu_endereco))[0])
                next_hop = self._next_hop(int2ip(src_addr))

                payload = struct.pack('!BBHi', 11, 0, 0, 0)  + datagrama[:28]
                checksum_ = calc_checksum(payload)
                payload = struct.pack('!BBHi', 11, 0, checksum_, 0) + datagrama[:28]

                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, 20+len(payload), identification, flagsfrag, ttl, IPPROTO_ICMP, \
                calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, 20+len(payload), identification, flagsfrag, ttl, IPPROTO_ICMP, \
                0, my_addr, src_addr)), my_addr, src_addr) + (payload)
                
                # print(next_hop)
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        ip_bin = int(struct.unpack('!I', str2addr(dest_addr))[0])
        for i in range(32, -1, -1):
            if i in self.tabela:
                if ((ip_bin >> 32-i) << 32-i) in self.tabela[i]:
                    return self.tabela[i][((ip_bin >> 32-i) << 32-i)]
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco
        pass
    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = defaultdict(lambda: {})
        for cidr, hop in tabela:
            aux = cidr.split('/')
            ip = aux[0]
            mask = int(aux[1])
            ip_bin = int(struct.unpack('!I', str2addr(ip))[0])
            ip_bin = (ip_bin >> (32-mask)) << (32-mask)
            self.tabela[mask][ip_bin] = hop
    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        vihl = 0x45
        ihl = 5
        identification = self.cont
        self.cont += 1
        ttl = 64
        proto = IPPROTO_TCP
        src_addr = str2addr(self.meu_endereco)
        dst_addr = str2addr(dest_addr)
        datagrama = struct.pack('!BBHHHBBH', vihl, 0, 20 + len(segmento), 
            identification, 0, ttl, proto, 0) +  src_addr + dst_addr
        checksum = calc_checksum(datagrama)
        datagrama = struct.pack('!BBHHHBBH', vihl, 0, 20 + len(segmento), 
            identification, 0, ttl, proto, checksum) + src_addr + dst_addr + segmento
        self.enlace.enviar(datagrama, next_hop)
