import asyncio
from tcputils import *
import random, time

TIMER_WAIT_VALUE = 0.3
ALPHA = 0.125
BETA = 0.25

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)
        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # random first seq_no
            init_seq_no = random.randint(0, (1<<10)+1)
            # swap dst_port <-> src_port
            # handshake -> send ACK+SYN
            response = make_header(dst_port, src_port, init_seq_no, (seq_no+1), FLAGS_SYN | FLAGS_ACK)
            response = fix_checksum(response, dst_addr, src_addr)
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, current_ack_no=init_seq_no+1, expected_seq_no=seq_no+len(payload)+1)
            conexao.servidor.rede.enviar(response, id_conexao[0])

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, current_ack_no, expected_seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.expected_seq_no = expected_seq_no
        self.current_ack_no = current_ack_no
        self.unACKed = []
        self.timeout_interval = TIMER_WAIT_VALUE
        self.send_time_dict = {}
        self.estimated_rtt = None
        self.dev_rtt = None
        self.bytes_queue = b''
        self.cwnd = 1
        self.last_ack_from_window = current_ack_no + MSS
        self.not_acked = b''
        self.timer = None

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        dst_addr, dst_port, src_addr, src_port  = self.id_conexao
        if seq_no == self.expected_seq_no:
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                response = make_header(src_port, dst_port, self.current_ack_no, \
                self.expected_seq_no + 1, FLAGS_ACK)
                response = fix_checksum(response, src_addr, dst_addr)
                self.servidor.rede.enviar(response, self.id_conexao[0])
                self.current_ack_no = ack_no
                if self.callback:
                    self.callback(self, b'')
            else:
                response = make_header(src_port, dst_port, self.current_ack_no, \
                self.expected_seq_no+len(payload), FLAGS_ACK)
                response = fix_checksum(response, src_addr, dst_addr)
                if len(payload) > 0: # if is only ACK, do not send response
                    # if no payload, expected_seq_no dont change
                    self.expected_seq_no = self.expected_seq_no + len(payload)
                    # send response for the payload
                    self.servidor.rede.enviar(response, self.id_conexao[0])
                    if self.callback:
                        self.callback(self, payload)
                if ack_no > self.current_ack_no:
                    # ignore retransmissions
                    self.not_acked = self.not_acked[(ack_no-self.current_ack_no):]
                    self.current_ack_no = ack_no
                    if ack_no >= self.last_ack_from_window:
                        self.cwnd += 1
                    if ack_no in self.send_time_dict:
                        
                        sample_rtt = time.time() - self.send_time_dict[ack_no]
                        if self.estimated_rtt != None and self.dev_rtt != None:
                            self.estimated_rtt = (1- ALPHA)*self.estimated_rtt + ALPHA*sample_rtt
                            self.dev_rtt = (1-BETA)*self.dev_rtt + BETA*abs(sample_rtt-self.estimated_rtt)
                            self.timeout_interval = self.estimated_rtt + 4*self.dev_rtt
                        else:
                            self.estimated_rtt = sample_rtt
                            self.dev_rtt = sample_rtt / 2
                            self.timeout_interval = self.estimated_rtt + 4*self.dev_rtt
                self.send_from_queue()


    def start_timer(self):
        if self.timer != None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self.send_from_not_acked)

    def send_from_not_acked(self):
        dst_addr, dst_port, src_addr, src_port  = self.id_conexao
        data = self.not_acked[:MSS]
        header = make_header(dst_port, src_port, self.current_ack_no, self.expected_seq_no, FLAGS_ACK)
        response = fix_checksum(header+data, src_addr, dst_addr)
        self.servidor.rede.enviar(response, self.id_conexao[0])

        self.last_ack_from_window -= (self.cwnd//2) * MSS
        self.cwnd = max(self.cwnd >> 1, 1)

        if self.current_ack_no+len(data) in self.send_time_dict:
            del self.send_time_dict[self.current_ack_no+len(data)]
        self.start_timer()

    def send_from_queue(self):
        qt_bytes = len(self.not_acked)
        i = 0
        while qt_bytes < self.cwnd * MSS:
            dst_addr, dst_port, src_addr, src_port  = self.id_conexao
            data = self.bytes_queue[:MSS]

            qt_bytes += len(data)
            if len(data) == 0:
                break
            self.bytes_queue = self.bytes_queue[MSS:]

            header = make_header(dst_port, src_port, self.current_ack_no+len(self.not_acked), self.expected_seq_no, FLAGS_ACK)
            self.not_acked += data
            
            response = fix_checksum(header+data, src_addr, dst_addr)
            self.send_time_dict[self.current_ack_no+len(self.not_acked)] = time.time() # possivel erro inverter com 138
            self.servidor.rede.enviar(response, self.id_conexao[0])

            i += 1
            self.last_ack_from_window = self.current_ack_no+len(self.not_acked)
        self.start_timer()

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        def truncate(x):
            if len(x) > max_size_payload:
                return x[:max_size_payload]
            else:
                return x
        dst_addr, dst_port, src_addr, src_port  = self.id_conexao
        
        max_size_payload = MSS
        
        self.bytes_queue += dados
        self.send_from_queue()
        
    def fechar(self):
        dst_addr, dst_port, src_addr, src_port  = self.id_conexao
        response = make_header(src_port, dst_port, self.current_ack_no, \
        self.expected_seq_no + 1, FLAGS_FIN)
        response = fix_checksum(response, src_addr, dst_addr)
        self.servidor.rede.enviar(response, self.id_conexao[0])

