from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
import re
import sys
import os

import argparse


def parse_k12_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Разделяем на блоки по разделителю
    blocks = content.split('+---------+---------------+----------+')
    packets = []
    
    for block in blocks:
        lines = block.strip().split('\n')
        if len(lines) < 2:
            continue
            
        # Извлекаем временную метку
        time_line = lines[0].strip()
        if not time_line:
            continue
            
        # Извлекаем hex дамп
        hex_line = lines[1].strip()
        if not hex_line.startswith('|0'):
            continue
            
        # Парсим временную метку
        time_match = re.match(r'(\d+:\d+:\d+),(\d+),(\d+)', time_line)
        if not time_match:
            continue
            
        time_str = f"{time_match.group(1)},{time_match.group(2)}{time_match.group(3)}"
        
        # Извлекаем hex байты
        hex_parts = []
        for part in hex_line.split('|')[1:]:
            part = part.strip()
            if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part):
                hex_parts.append(part)
        
        if not hex_parts:
            continue
            
        hex_bytes = bytes.fromhex(''.join(hex_parts))
        
        packets.append((time_str, hex_bytes))
    
    return packets

def format_packet(time_str, packet_data):
    try:
        # Парсим пакет с помощью Scapy
        pkt = Ether(packet_data)
        
        output = f"{time_str} "
        
        if IP in pkt:
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto
            
            if TCP in pkt:
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                
                # Формируем информацию о флагах
                flags = []
                if tcp.flags & 0x02: flags.append('S')  # SYN
                if tcp.flags & 0x10: flags.append('A')  # ACK
                if tcp.flags & 0x01: flags.append('F')  # FIN
                if tcp.flags & 0x04: flags.append('R')  # RST
                if tcp.flags & 0x08: flags.append('P')  # PUSH
                if tcp.flags & 0x20: flags.append('U')  # URG
                
                flags_str = ''.join(flags) if flags else '.'
                
                # Последовательность и подтверждение
                seq = tcp.seq
                ack = tcp.ack
                win = tcp.window
                
                # Длина данных
                data_len = len(tcp.payload)
                
                # Формируем вывод
                if flags_str == 'S':  # SYN пакет
                    output += f"IP {src_ip}.{sport} > {dst_ip}.{dport}: S {seq}:{seq}(0) win {win}"
                    # Добавляем опции если есть
                    if tcp.options:
                        options = []
                        for opt in tcp.options:
                            if opt[0] == 'MSS':
                                options.append(f"mss {opt[1]}")
                            elif opt[0] == 'NOP':
                                options.append("nop")
                            elif opt[0] == 'SAckOK':
                                options.append("sackOK")
                            elif opt[0] == 'WScale':
                                options.append(f"wscale {opt[1]}")
                        if options:
                            output += f" <{','.join(options)}>"
                
                elif flags_str == 'SA':  # SYN-ACK пакет
                    output += f"IP {src_ip}.{sport} > {dst_ip}.{dport}: S {seq}:{seq}(0) ack {ack} win {win}"
                    if tcp.options:
                        options = []
                        for opt in tcp.options:
                            if opt[0] == 'MSS':
                                options.append(f"mss {opt[1]}")
                            elif opt[0] == 'NOP':
                                options.append("nop")
                            elif opt[0] == 'SAckOK':
                                options.append("sackOK")
                        if options:
                            output += f" <{','.join(options)}>"
                
                elif flags_str == 'A':  # ACK пакет
                    if data_len > 0:
                        output += f"IP {src_ip}.{sport} > {dst_ip}.{dport}: . {seq}:{seq+data_len}({data_len}) ack {ack} win {win}"
                    else:
                        output += f"IP {src_ip}.{sport} > {dst_ip}.{dport}: . ack {ack} win {win}"
                
                elif flags_str == 'F':  # FIN пакет
                    output += f"IP {src_ip}.{sport} > {dst_ip}.{dport}: F {seq}:{seq}(0) ack {ack} win {win}"
                
                else:
                    output += f"IP {src_ip}.{sport} > {dst_ip}.{dport}: {flags_str} {seq}:{seq+data_len}({data_len}) ack {ack} win {win}"
            
            elif UDP in pkt:
                udp = pkt[UDP]
                output += f"IP {src_ip}.{udp.sport} > {dst_ip}.{udp.dport}: UDP, length {len(udp.payload)}"
            
            elif ICMP in pkt:
                icmp = pkt[ICMP]
                output += f"IP {src_ip} > {dst_ip}: ICMP type {icmp.type}, code {icmp.code}"
            
            else:
                output += f"IP {src_ip} > {dst_ip}: protocol {proto}"
        
        elif ARP in pkt:
            arp = pkt[ARP]
            if arp.op == 1:  # ARP Request
                output += f"ARP, Request who-has {arp.pdst} tell {arp.psrc}, length {len(packet_data)}"
            elif arp.op == 2:  # ARP Reply
                output += f"ARP, Reply {arp.psrc} is-at {arp.hwsrc}, length {len(packet_data)}"
            else:
                output += f"ARP, opcode {arp.op}"
        
        else:
            output += f"ETHER type 0x{pkt.type:04x}"
        
        return output
        
    except Exception as e:
        return f"{time_str} Error parsing packet: {str(e)}"

def main():
    parser = argparse.ArgumentParser(
        prog='k12_parser',
        description='Парсер capture-файлов в формате K12',
        epilog='Пример: python k12_parser.py captured_packets.txt'
    )
    
    parser.add_argument(
        'input_file',
        type=str,
        help='Путь к входному файлу в формате K12'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Файл для сохранения результата (опционально)'
    )
    
    parser.add_argument(
        '-n', '--count',
        type=int,
        default=0,
        help='Количество выводимых пакетов (по умолчанию все)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Подробный вывод (с отладочной информацией)'
    )
    
    args = parser.parse_args()
    
    # Проверяем существование файла
    if not os.path.exists(args.input_file):
        print(f"Файл '{args.input_file}' не найден")
        print(f"   Текущая директория: {os.getcwd()}")
        sys.exit(1)
    
    
    
    if os.path.getsize(args.input_file) == 0:
        print(f"Файл '{args.input_file}' пуст")
        sys.exit(0)
    
   
    packets = parse_k12_file(args.input_file)
    
    if packets is None:
        sys.exit(1)
    
    if not packets:
        print(f"В файле '{args.input_file}' не найдено пакетов в формате K12")
        sys.exit(0)
    
    
    output_lines = []
    packet_count = len(packets)
    
    if args.count > 0:
        packet_count = min(args.count, len(packets))
    
    for i in range(packet_count):
        time_str, packet_data = packets[i]
        formatted = format_packet(time_str, packet_data)
        output_lines.append(formatted)
 
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                for line in output_lines:
                    f.write(line + '\n')
            print(f"Результат сохранен в '{args.output}'")
        except Exception as e:
            print(f"Ошибка при сохранении: {e}")
            sys.exit(1)
    else:
        
        print("\n" + "=" * 60)
        print(f"Анализ пакетов из файла: {args.input_file}")
        print("=" * 60)
        for line in output_lines:
            print(line)


if __name__ == "__main__":
    main()