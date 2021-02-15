import struct
zero = b'\xc0'

class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        self.enlaces = {}
        self.callback = None
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.current_data = b''
        self.st_1 = False
        self.st_2 = False
    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        datagrama = bytearray(datagrama)
        datagrama_p = []
        for i, j in enumerate(datagrama):
            if(datagrama[i] == 0xC0):
                datagrama_p += b'\xdb\xdc' 
            elif(datagrama[i] == 0xDB):
                datagrama_p += b'\xdb\xdd' 
            else:
                datagrama_p += (int.to_bytes(j, length=1, byteorder="big")) 
        datagrama_p = zero + bytearray(datagrama_p) + zero
        self.linha_serial.enviar(datagrama_p)

    def __raw_recv(self, dados):
        zero = 0xC0
        data_send = b''
        
        for i, j in enumerate(dados):
            if(j == 0xDB):
                self.st_1 = self.st_2 = True
            elif(self.st_1 and j == 0xDC):
                self.current_data += (int.to_bytes(0xC0, length=1, byteorder="big")) 
                self.st_1 = self.st_2 = False
            elif(self.st_2 and j == 0xDD):
                self.current_data += (int.to_bytes(0xDB, length=1, byteorder="big")) 
                self.st_1 = self.st_2 = False
            elif j == zero:
                self.st_1 = self.st_2 = False
                data_send = self.current_data
                if (len(data_send) != 0):
                    try:
                        self.callback(data_send)
                    except:
                        import traceback
                        traceback.print_exc()
                    self.current_data = b''
            else:
                self.current_data += (int.to_bytes(j, length=1, byteorder="big")) 
