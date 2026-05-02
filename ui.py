import sys
import os
from collections import deque
from PySide6.QtWidgets import (QApplication, QMainWindow, QDialog, QVBoxLayout, 
                               QHBoxLayout, QListWidget, QPushButton, QLabel, 
                               QLineEdit, QSpinBox, QMessageBox, QTabWidget,
                               QGroupBox, QGridLayout, QWidget, QComboBox, QCheckBox)
from PySide6.QtCore import QTimer, Qt, QRect
from PySide6.QtGui import QFont

# Add current directory to path to import packet_sender
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from packet_sender import PacketSender, NetworkUtils

class PacketQueueDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Queue Manager")
        self.setGeometry(100, 100, 700, 500)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Packet Queue Manager")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Queue list
        queue_group = QGroupBox("Packet Queue")
        queue_layout = QVBoxLayout()
        self.queue_list = QListWidget()
        self.queue_list.setMinimumHeight(200)
        queue_layout.addWidget(self.queue_list)
        queue_group.setLayout(queue_layout)
        layout.addWidget(queue_group)
        
        # Controls
        controls_group = QGroupBox("Queue Settings")
        controls_layout = QGridLayout()
        
        controls_layout.addWidget(QLabel("Interval (seconds):"), 0, 0)
        self.interval_input = QLineEdit()
        self.interval_input.setPlaceholderText("1.0")
        self.interval_input.setText("1.0")
        controls_layout.addWidget(self.interval_input, 0, 1)
        
        controls_layout.addWidget(QLabel("Repeat count:"), 1, 0)
        self.repeat_input = QSpinBox()
        self.repeat_input.setRange(1, 1000)
        self.repeat_input.setValue(1)
        controls_layout.addWidget(self.repeat_input, 1, 1)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        
        self.add_button = QPushButton("Add to Queue")
        self.add_button.clicked.connect(self.add_current_packet)
        buttons_layout.addWidget(self.add_button)
        
        self.remove_button = QPushButton("Remove")
        self.remove_button.clicked.connect(self.remove_selected)
        buttons_layout.addWidget(self.remove_button)
        
        self.clear_button = QPushButton("Clear All")
        self.clear_button.clicked.connect(self.clear_queue)
        buttons_layout.addWidget(self.clear_button)
        
        layout.addLayout(buttons_layout)
        
        # Send button
        self.send_button = QPushButton("Send Queue")
        self.send_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        self.send_button.clicked.connect(self.send_queue)
        layout.addWidget(self.send_button)
        
        # Status
        self.status_label = QLabel("Ready - Queue is empty")
        self.status_label.setStyleSheet("QLabel { padding: 5px; background-color: #f0f0f0; border: 1px solid #ccc; }")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
    def add_current_packet(self):
        main_window = self.parent()
        if hasattr(main_window, 'create_packet'):
            packet_info = main_window.create_packet()
            if packet_info:
                try:
                    interval = float(self.interval_input.text() or 1.0)
                except ValueError:
                    interval = 1.0
                    self.interval_input.setText("1.0")
                    
                repeat = self.repeat_input.value()
                
                queue_item = {
                    'packet': packet_info['packet'],
                    'packet_info': packet_info,
                    'interval': interval,
                    'repeat': repeat
                }
                
                main_window.packet_sender.packet_queue.append(queue_item)
                self.update_queue_display()
                QMessageBox.information(self, "Success", "Packet added to queue!")
    
    def remove_selected(self):
        main_window = self.parent()
        current_row = self.queue_list.currentRow()
        if current_row >= 0 and current_row < len(main_window.packet_sender.packet_queue):
            queue_list = list(main_window.packet_sender.packet_queue)
            queue_list.pop(current_row)
            main_window.packet_sender.packet_queue = deque(queue_list)
            self.update_queue_display()
    
    def clear_queue(self):
        main_window = self.parent()
        if main_window.packet_sender.packet_queue:
            reply = QMessageBox.question(self, "Clear Queue", 
                                       "Are you sure you want to clear the entire queue?",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                main_window.packet_sender.packet_queue.clear()
                self.update_queue_display()
    
    def send_queue(self):
        main_window = self.parent()
        if hasattr(main_window, 'send_packet_queue'):
            if not main_window.packet_sender.packet_queue:
                QMessageBox.warning(self, "Empty Queue", "Queue is empty! Add packets first.")
                return
            main_window.send_packet_queue()
    
    def update_queue_display(self):
        main_window = self.parent()
        self.queue_list.clear()
        
        for i, item in enumerate(main_window.packet_sender.packet_queue):
            packet_info = item['packet_info']
            text = f"{i+1}. {packet_info['type']} | Src: {packet_info['src']} -> Dst: {packet_info['dst']} | "
            text += f"Interval: {item['interval']}s | Repeat: {item['repeat']}x"
            self.queue_list.addItem(text)
        
        queue_size = len(main_window.packet_sender.packet_queue)
        self.status_label.setText(f"Queue: {queue_size} packet{'s' if queue_size != 1 else ''}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Initialize packet sender with logic
        self.packet_sender = PacketSender()
        self.is_sending_queue = False
        
        self.setup_ui()
        
        # Setup protocols
        self.setup_protocols()
        
        # Connect signals
        self.TransportLayer.currentTextChanged.connect(self.switch_transport_tab)
        self.autoMAC.clicked.connect(self.auto_detect_mac_address)
        self.SendButton.clicked.connect(self.send_single_packet)
        self.arp_button.clicked.connect(self.refresh_arp_table)
        self.queue_button.clicked.connect(self.show_queue_dialog)
        
        # Connect interface selection to auto-fill
        self.Interfaces.currentTextChanged.connect(self.on_interface_selected)
        
        # Auto-fill for first interface
        self.on_interface_selected()
        
        self.queue_dialog = None

    def on_interface_selected(self):
        """Automatically fill network settings when interface is selected"""
        interface = self.Interfaces.currentText()
        if interface:
            try:
                # Get IP and netmask
                ip, netmask = NetworkUtils.get_interface_info(interface)
                if ip:
                    self.SourceIP.setText(ip)
                if netmask:
                    self.Netmask.setText(netmask)
                
                # Get gateway
                gateway = NetworkUtils.get_gateway_info(interface)
                if gateway:
                    self.Gateway.setText(gateway)
                
                # Auto-detect source MAC
                try:
                    src_mac = get_if_hwaddr(interface)
                    self.SourceMAC.setText(src_mac)
                except:
                    pass
                    
            except Exception as e:
                print(f"Error auto-filling interface info: {e}")

    def setup_ui(self):
        """Setup basic UI elements"""
        self.setWindowTitle("Packet Crafter - Генератор сетевых пакетов")
        self.setGeometry(100, 100, 900, 1000)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Network settings group
        network_group = QGroupBox("Настройки сети (Network Settings)")
        network_layout = QGridLayout()
        
        # Interface selection
        network_layout.addWidget(QLabel("Интерфейс (Interface):"), 0, 0)
        self.Interfaces = QComboBox()
        
        # Get available interfaces
        interfaces = NetworkUtils.get_network_interfaces()
        if interfaces:
            self.Interfaces.addItems(interfaces)
        else:
            self.Interfaces.addItems(["eth0", "wlan0"])  # Fallback
        
        network_layout.addWidget(self.Interfaces, 0, 1)
        
        # Source IP
        network_layout.addWidget(QLabel("IP источника (Source IP):"), 0, 2)
        self.SourceIP = QLineEdit()
        self.SourceIP.setPlaceholderText("Автоматически определится")
        network_layout.addWidget(self.SourceIP, 0, 3)
        
        # Destination IP
        network_layout.addWidget(QLabel("IP назначения (Destination IP):"), 1, 0)
        self.DestinationIP = QLineEdit()
        self.DestinationIP.setPlaceholderText("Обязательное поле")
        network_layout.addWidget(self.DestinationIP, 1, 1)
        
        # Source MAC
        network_layout.addWidget(QLabel("MAC источника (Source MAC):"), 1, 2)
        self.SourceMAC = QLineEdit()
        self.SourceMAC.setPlaceholderText("Автоматически определится")
        network_layout.addWidget(self.SourceMAC, 1, 3)
        
        # Destination MAC
        network_layout.addWidget(QLabel("MAC назначения (Destination MAC):"), 2, 0)
        self.DestinationMAC = QLineEdit()
        self.DestinationMAC.setText("FF:FF:FF:FF:FF:FF")
        self.DestinationMAC.setPlaceholderText("Определится автоматически")
        network_layout.addWidget(self.DestinationMAC, 2, 1)
        
        # Transport layer selection
        network_layout.addWidget(QLabel("Протокол (Protocol):"), 2, 2)
        self.TransportLayer = QComboBox()
        self.TransportLayer.addItems(["TCP", "UDP", "ICMP"])
        network_layout.addWidget(self.TransportLayer, 2, 3)
        
        # Netmask
        network_layout.addWidget(QLabel("Маска подсети (Netmask):"), 3, 0)
        self.Netmask = QLineEdit()
        self.Netmask.setPlaceholderText("255.255.255.0")
        network_layout.addWidget(self.Netmask, 3, 1)
        
        # Gateway
        network_layout.addWidget(QLabel("Шлюз (Gateway):"), 3, 2)
        self.Gateway = QLineEdit()
        self.Gateway.setPlaceholderText("Автоматически определится")
        network_layout.addWidget(self.Gateway, 3, 3)
        
        network_group.setLayout(network_layout)
        main_layout.addWidget(network_group)
        
        # IP Header fields group
        ip_group = QGroupBox("Заголовок IP (IP Header)")
        ip_layout = QGridLayout()
        
        # IP header fields
        ip_layout.addWidget(QLabel("ID:"), 0, 0)
        self.ID = QLineEdit()
        self.ID.setPlaceholderText("Авто")
        ip_layout.addWidget(self.ID, 0, 1)
        
        ip_layout.addWidget(QLabel("TTL:"), 0, 2)
        self.TTL = QLineEdit()
        self.TTL.setText("64")
        ip_layout.addWidget(self.TTL, 0, 3)
        
        ip_layout.addWidget(QLabel("Длина заголовка (Header Len):"), 1, 0)
        self.HeaderLen = QLineEdit()
        self.HeaderLen.setPlaceholderText("Авто")
        ip_layout.addWidget(self.HeaderLen, 1, 1)
        
        ip_layout.addWidget(QLabel("Длина пакета (Packet Len):"), 1, 2)
        self.PacketLen = QLineEdit()
        self.PacketLen.setPlaceholderText("Авто")
        ip_layout.addWidget(self.PacketLen, 1, 3)
        
        ip_layout.addWidget(QLabel("Смещение фрагмента (Frag Offset):"), 2, 0)
        self.FragmentationOffset = QLineEdit()
        self.FragmentationOffset.setText("0")
        ip_layout.addWidget(self.FragmentationOffset, 2, 1)
        
        ip_layout.addWidget(QLabel("Контрольная сумма (Checksum):"), 2, 2)
        self.HeaderChecksum = QLineEdit()
        self.HeaderChecksum.setPlaceholderText("Авто")
        ip_layout.addWidget(self.HeaderChecksum, 2, 3)
        
        ip_group.setLayout(ip_layout)
        main_layout.addWidget(ip_group)
        
        # Create tab widget for different protocols
        self.tabWidget = QTabWidget()
        
        # TCP tab
        self.tcp_tab = QWidget()
        tcp_layout = QGridLayout(self.tcp_tab)
        self.setup_tcp_tab(tcp_layout)
        self.tabWidget.addTab(self.tcp_tab, "TCP")
        
        # UDP tab
        self.udp_tab = QWidget()
        udp_layout = QGridLayout(self.udp_tab)
        self.setup_udp_tab(udp_layout)
        self.tabWidget.addTab(self.udp_tab, "UDP")
        
        # ICMP tab
        self.icmp_tab = QWidget()
        icmp_layout = QGridLayout(self.icmp_tab)
        self.setup_icmp_tab(icmp_layout)
        self.tabWidget.addTab(self.icmp_tab, "ICMP")
        
        main_layout.addWidget(self.tabWidget)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.autoMAC = QPushButton("Автоопределение MAC")
        self.autoMAC.setStyleSheet("QPushButton { background-color: #FF9800; color: white; font-weight: bold; }")
        button_layout.addWidget(self.autoMAC)
        
        self.arp_button = QPushButton("🔄 ARP")
        self.arp_button.setToolTip("Обновить ARP таблицу")
        button_layout.addWidget(self.arp_button)
        
        self.SendButton = QPushButton("Отправить пакет")
        self.SendButton.setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; }")
        button_layout.addWidget(self.SendButton)
        
        self.queue_button = QPushButton("Управление очередью")
        self.queue_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        button_layout.addWidget(self.queue_button)
        
        main_layout.addLayout(button_layout)
        
        # Apply styling
        self.apply_styling()

    # Остальные методы setup_tcp_tab, setup_udp_tab, setup_icmp_tab остаются без изменений
    def setup_tcp_tab(self, layout):
        """Setup TCP tab with all fields"""
        # Source port
        layout.addWidget(QLabel("Порт источника:"), 0, 0)
        self.TCPSrcPort = QLineEdit()
        self.TCPSrcPort.setPlaceholderText("Авто")
        layout.addWidget(self.TCPSrcPort, 0, 1)
        
        # Destination port
        layout.addWidget(QLabel("Порт назначения:"), 0, 2)
        self.TCPDstPort = QLineEdit()
        self.TCPDstPort.setPlaceholderText("Обязательно")
        layout.addWidget(self.TCPDstPort, 0, 3)
        
        # Sequence number
        layout.addWidget(QLabel("Номер последовательности:"), 1, 0)
        self.TCPSeqNum = QLineEdit()
        self.TCPSeqNum.setPlaceholderText("Авто")
        layout.addWidget(self.TCPSeqNum, 1, 1)
        
        # Acknowledgment number
        layout.addWidget(QLabel("Номер подтверждения:"), 1, 2)
        self.TCPAckNum = QLineEdit()
        self.TCPAckNum.setPlaceholderText("0")
        layout.addWidget(self.TCPAckNum, 1, 3)
        
        # TCP flags
        flags_group = QGroupBox("TCP Флаги")
        flags_layout = QGridLayout()
        
        self.TCPSYN = QCheckBox("SYN")
        flags_layout.addWidget(self.TCPSYN, 0, 0)
        self.TCPFIN = QCheckBox("FIN")
        flags_layout.addWidget(self.TCPFIN, 0, 1)
        self.TCPRST = QCheckBox("RST")
        flags_layout.addWidget(self.TCPRST, 0, 2)
        self.TCPPUSH = QCheckBox("PSH")
        flags_layout.addWidget(self.TCPPUSH, 0, 3)
        
        self.TCPACK = QCheckBox("ACK")
        flags_layout.addWidget(self.TCPACK, 1, 0)
        self.TCPURG = QCheckBox("URG")
        flags_layout.addWidget(self.TCPURG, 1, 1)
        self.TCPECNEcho = QCheckBox("ECE")
        flags_layout.addWidget(self.TCPECNEcho, 1, 2)
        self.TCPCWR = QCheckBox("CWR")
        flags_layout.addWidget(self.TCPCWR, 1, 3)
        
        flags_group.setLayout(flags_layout)
        layout.addWidget(flags_group, 2, 0, 1, 4)
        
        # Additional TCP fields
        layout.addWidget(QLabel("Смещение данных:"), 3, 0)
        self.TCPDataOffset = QLineEdit()
        self.TCPDataOffset.setPlaceholderText("Авто")
        layout.addWidget(self.TCPDataOffset, 3, 1)
        
        layout.addWidget(QLabel("Размер окна:"), 3, 2)
        self.TCPWindowSize = QLineEdit()
        self.TCPWindowSize.setText("8192")
        layout.addWidget(self.TCPWindowSize, 3, 3)
        
        layout.addWidget(QLabel("Контрольная сумма:"), 4, 0)
        self.TCPChecksum = QLineEdit()
        self.TCPChecksum.setPlaceholderText("Авто")
        layout.addWidget(self.TCPChecksum, 4, 1)
        
        layout.addWidget(QLabel("Указатель срочности:"), 4, 2)
        self.TCPUrgPtr = QLineEdit()
        self.TCPUrgPtr.setText("0")
        layout.addWidget(self.TCPUrgPtr, 4, 3)
        
        # TCP payload
        layout.addWidget(QLabel("Данные (hex):"), 5, 0)
        self.TCPPayload = QLineEdit()
        self.TCPPayload.setPlaceholderText("HEX данные (без 0x)")
        layout.addWidget(self.TCPPayload, 5, 1, 1, 3)

    def setup_udp_tab(self, layout):
        """Setup UDP tab with all fields"""
        # Source port
        layout.addWidget(QLabel("Порт источника:"), 0, 0)
        self.UDPSrcPort = QLineEdit()
        self.UDPSrcPort.setPlaceholderText("Авто")
        layout.addWidget(self.UDPSrcPort, 0, 1)
        
        # Destination port
        layout.addWidget(QLabel("Порт назначения:"), 0, 2)
        self.UDPDstPort = QLineEdit()
        self.UDPDstPort.setPlaceholderText("Обязательно")
        layout.addWidget(self.UDPDstPort, 0, 3)
        
        # Additional UDP fields
        layout.addWidget(QLabel("Длина:"), 1, 0)
        self.UDPLen = QLineEdit()
        self.UDPLen.setPlaceholderText("Авто")
        layout.addWidget(self.UDPLen, 1, 1)
        
        layout.addWidget(QLabel("Контрольная сумма:"), 1, 2)
        self.UDPChecksum = QLineEdit()
        self.UDPChecksum.setPlaceholderText("Авто")
        layout.addWidget(self.UDPChecksum, 1, 3)
        
        # UDP payload
        layout.addWidget(QLabel("Данные (hex):"), 2, 0)
        self.UDPPayload = QLineEdit()
        self.UDPPayload.setPlaceholderText("HEX данные (без 0x)")
        layout.addWidget(self.UDPPayload, 2, 1, 1, 3)

    def setup_icmp_tab(self, layout):
        """Setup ICMP tab with all fields"""
        # ICMP type
        layout.addWidget(QLabel("Тип ICMP:"), 0, 0)
        self.ICMPTypes = QComboBox()
        self.ICMPTypes.addItems(["Echo Request", "Echo Reply"])
        layout.addWidget(self.ICMPTypes, 0, 1)
        
        # ICMP code
        layout.addWidget(QLabel("Код:"), 0, 2)
        self.ICMPCode = QLineEdit()
        self.ICMPCode.setText("0")
        layout.addWidget(self.ICMPCode, 0, 3)
        
        # ICMP identifier
        layout.addWidget(QLabel("Идентификатор:"), 1, 0)
        self.ICMPId = QLineEdit()
        self.ICMPId.setPlaceholderText("Авто")
        layout.addWidget(self.ICMPId, 1, 1)
        
        # ICMP sequence number
        layout.addWidget(QLabel("Номер последовательности:"), 1, 2)
        self.ICMPSeqNum = QLineEdit()
        self.ICMPSeqNum.setPlaceholderText("Авто")
        layout.addWidget(self.ICMPSeqNum, 1, 3)
        
        # ICMP checksum
        layout.addWidget(QLabel("Контрольная сумма:"), 2, 0)
        self.ICMPChecksum = QLineEdit()
        self.ICMPChecksum.setPlaceholderText("Авто")
        layout.addWidget(self.ICMPChecksum, 2, 1)
        
        # ICMP payload
        layout.addWidget(QLabel("Данные (hex):"), 3, 0)
        self.ICMPPayload = QLineEdit()
        self.ICMPPayload.setPlaceholderText("HEX данные (без 0x)")
        layout.addWidget(self.ICMPPayload, 3, 1, 1, 3)

    def apply_styling(self):
        """Apply modern styling to the UI"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QLineEdit, QComboBox, QSpinBox {
                padding: 5px;
                border: 1px solid #cccccc;
                border-radius: 3px;
                background-color: white;
            }
            QLabel {
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid #C2C7CB;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #E1E1E1;
                border: 1px solid #C4C4C3;
                padding: 8px 20px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #2196F3;
                color: white;
            }
        """)

    # Остальные методы без изменений
    def setup_protocols(self):
        """Set up protocols"""
        # Set initial transport tab
        self.switch_transport_tab(self.TransportLayer.currentText())

    def switch_transport_tab(self, protocol):
        """Switch to the appropriate transport protocol tab"""
        if protocol == "TCP":
            self.tabWidget.setCurrentWidget(self.tcp_tab)
        elif protocol == "UDP":
            self.tabWidget.setCurrentWidget(self.udp_tab)
        elif protocol == "ICMP":
            self.tabWidget.setCurrentWidget(self.icmp_tab)

    def auto_detect_mac_address(self):
        """Smart automatic MAC address detection using NetworkUtils"""
        try:
            target_ip = self.DestinationIP.text().strip()
            if not target_ip:
                QMessageBox.warning(self, "Предупреждение", "Введите IP-адрес назначения")
                return
            
            # Get current interface settings
            interface_ip = self.SourceIP.text().strip()
            netmask_text = self.Netmask.text().strip() if self.Netmask.text().strip() else "255.255.255.0"
            gateway_text = self.Gateway.text().strip() if self.Gateway.text().strip() else NetworkUtils.get_gateway_info()
            
            if not interface_ip:
                QMessageBox.warning(self, "Предупреждение", "Сначала настройте сетевой интерфейс")
                return
            
            # Get ARP table
            arp_table = NetworkUtils.get_arp_table()
            
            # Calculate optimal MAC address
            destination_mac, warning_msg = NetworkUtils.calculate_optimal_mac(
                target_ip, interface_ip, netmask_text, gateway_text, arp_table
            )
            
            # Set calculated MAC
            self.DestinationMAC.setText(destination_mac)
            
            if warning_msg:
                QMessageBox.warning(self, "Предупреждение", warning_msg)
            else:
                QMessageBox.information(self, "Информация", f"Автоматически определен MAC: {destination_mac}")
            
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка автоматического определения: {str(e)}")
            # In case of error, use broadcast
            self.DestinationMAC.setText("FF:FF:FF:FF:FF:FF")

    def refresh_arp_table(self):
        """Refresh ARP table for the target IP"""
        try:
            target_ip = self.DestinationIP.text().strip()
            if target_ip:
                success, message = NetworkUtils.refresh_arp_table(target_ip)
                if success:
                    QMessageBox.information(self, "Информация", message)
                else:
                    QMessageBox.warning(self, "Предупреждение", message)
            else:
                QMessageBox.warning(self, "Предупреждение", "Введите IP-адрес для обновления ARP")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка обновления ARP: {e}")


    def show_queue_dialog(self):
        if self.queue_dialog is None:
            self.queue_dialog = PacketQueueDialog(self)
        self.queue_dialog.show()
        self.queue_dialog.raise_()
        self.queue_dialog.activateWindow()
        self.queue_dialog.update_queue_display()

    def create_packet(self):
        """Create packet from current UI settings without sending it"""
        current_transport_layer = self.TransportLayer.currentText()
        interface = self.Interfaces.currentText()
        
        return self.packet_sender.create_packet(self, current_transport_layer, interface)

    def send_single_packet(self):
        """Send a single packet from current UI settings"""
        packet_info = self.create_packet()
        success, message = self.packet_sender.send_single_packet(packet_info)
        
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Send Error", message)

    def send_packet_queue(self):
        """Start sending the packet queue"""
        if not self.packet_sender.packet_queue:
            QMessageBox.information(self, "Queue Empty", "Packet queue is empty!")
            return
        
        if self.packet_sender.is_sending_queue:
            QMessageBox.information(self, "Already Sending", "Queue is already being sent!")
            return
        
        self.packet_sender.is_sending_queue = True
        
        if self.queue_dialog:
            self.queue_dialog.status_label.setText("Sending queue...")
            self.queue_dialog.send_button.setEnabled(False)
        
        # Create a flat list of all packets to send with their intervals
        self.flat_queue = []
        for item in self.packet_sender.packet_queue:
            for _ in range(item['repeat']):
                # Сохраняем всю информацию из packet_info
                self.flat_queue.append({
                    'packet': item['packet'],
                    'interface': item['packet_info']['interface'],
                    'src': item['packet_info']['src'],  # Добавьте это
                    'dst': item['packet_info']['dst'],  # Добавьте это
                    'type': item['packet_info']['type'],  # Добавьте это
                    'interval': item['interval']
                })
        
        self.current_packet_index = 0
        self.send_next_queued_packet()
    def send_next_queued_packet(self):
        """Send the next packet in queue"""
        if not self.flat_queue or self.current_packet_index >= len(self.flat_queue):
            # Queue finished
            self.packet_sender.is_sending_queue = False
            
            if self.queue_dialog:
                self.queue_dialog.status_label.setText("Queue sending completed!")
                self.queue_dialog.send_button.setEnabled(True)
                self.queue_dialog.update_queue_display()
            
            QMessageBox.information(self, "Queue Complete", "All packets in queue have been sent!")
            return
        
        # Get current packet
        current_item = self.flat_queue[self.current_packet_index]
        
        try:
            print(f"Sending packet {self.current_packet_index + 1}/{len(self.flat_queue)}")
            
            packet_info = {
                'packet': current_item['packet'],
                'interface': current_item['interface'],
                'src': current_item.get('src', 'auto'),
                'dst': current_item.get('dst', 'auto'),
                'type': current_item.get('type', 'UNKNOWN')
            }
            
            # Send the packet
            success, message = self.packet_sender.send_single_packet(packet_info)
            
            if success:
                print("Packet sent successfully!")
                
                # Удаляем отправленный пакет из основной очереди
                if self.current_packet_index < len(self.packet_sender.packet_queue):
                    # Преобразуем deque в список, удаляем элемент, и обратно в deque
                    queue_list = list(self.packet_sender.packet_queue)
                    if queue_list:  # Проверяем, что список не пустой
                        queue_list.pop(0)  # Удаляем первый элемент (текущий пакет)
                        self.packet_sender.packet_queue = deque(queue_list)
                
                if self.queue_dialog:
                    status = f"Sending: {self.current_packet_index + 1}/{len(self.flat_queue)}"
                    self.queue_dialog.status_label.setText(status)
                    self.queue_dialog.update_queue_display()  # Обновляем отображение после удаления
                
                # Move to next packet
                self.current_packet_index += 1
                
                # Schedule next packet if there are more
                if self.current_packet_index < len(self.flat_queue):
                    next_interval = self.flat_queue[self.current_packet_index]['interval'] * 1000
                    QTimer.singleShot(int(next_interval), self.send_next_queued_packet)
                else:
                    # Queue finished
                    self.packet_sender.is_sending_queue = False
                    if self.queue_dialog:
                        self.queue_dialog.status_label.setText("Queue sending completed!")
                        self.queue_dialog.send_button.setEnabled(True)
            else:
                raise Exception(message)
                    
        except Exception as e:
            error_msg = f"Error sending packet {self.current_packet_index + 1}: {str(e)}"
            print(f"Error: {error_msg}")
            if self.queue_dialog:
                self.queue_dialog.status_label.setText(f"Error: {str(e)}")
                self.queue_dialog.send_button.setEnabled(True)
                self.queue_dialog.update_queue_display()
            QMessageBox.critical(self, "Send Error", error_msg)
            self.packet_sender.is_sending_queue = False

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()