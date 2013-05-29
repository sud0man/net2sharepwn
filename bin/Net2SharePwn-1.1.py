#! /usr/bin/python2.5
# -*- coding: iso-8859-15 -*-

import sys, os
sys.path.append('/usr/bin') # Repertoire d'installation de Scapy
#from scapy.all import *
import time
import os.path
import re


#forme
###################################################################################################################
#print color
###################################################################################################################
def print_resgood(text) :
	print ('\033[0;32m' + text + '\033[1;m')

def print_resfail(text) :
	print ('\033[0;31m' + text + '\033[1;m')


def print_in(text) :
	print ('\033[0;44m' + text + '\033[1;m')

def print_info(text) :
	print ('\033[0;28m' + text + '\033[1;m')
	
def print_info2(text) :
	print ('\033[0;31m' + text + '\033[1;m')

def print_log(text) :
	print ('\033[0;37m' + text + '\033[1;m')

def print_ls(text) :
	print ('\033[0;33m' + text + '\033[1;m')

###################################################################################################################
#raw_input color
###################################################################################################################
def raw_input_resgood(text) :
	res=raw_input ('\033[0;32m' + text + '\033[1;m')
	return res

def raw_input_resfail(text) :
	res=raw_input ('\033[0;31m' + text + '\033[1;m')
	return res

def raw_input_in(text) :
	res=raw_input ('\033[0;44m' + text + '\033[1;m')
	return res

def raw_input_info(text) :
	res=raw_input ('\033[0;33m' + text + '\033[1;m')
	return res

def raw_input_log(text) :
	res=raw_input ('\033[0;37m' + text + '\033[1;m')
	return res





###################################################################################################################		
#ls-l
###################################################################################################################	
def list_output(tag,outputdir):
	res=os.popen('ls ' + outputdir + '| grep ' + tag).read()
	print_ls(res)
	#res=os.system('ls ' + outputdir + '| grep ' + tag + '> ' + outputdir + '/tag.txt')
	#file=open(outputdir + "/tag.txt",'r')
	#d1=file.readlines()
	#for i in range(len(d1)):
	#	d2=d1[i].strip("\n")
	#	print d2
	# os.system('rm ' + outputdir + '/tag.txt')
###################################################################################################################	


###################################################################################################################
#13:MAIN:commande système
###################################################################################################################
def option13(auth,proj,outputdir):
	cmd=raw_input_in(">>IN> CMD (q pour quitter)>")
	if cmd =="q" or cmd =="Q" : menu(auth,proj,outputdir)
	else : 
		os.system(cmd)
		option13(auth,proj,outputdir)
###################################################################################################################


###################################################################################################################
def option11():
	main()

###################################################################################################################





###################################################################################################################
###################################################################################################################
#variable globale
smb_auth="auth/smb-auth.txt"
smb_auth2="auth/smb-auth2.txt"
check_os = os.popen('uname').read() 
if "Darwin" in check_os :
	os_used="Mac"
	mountrep="/Volumes"
	print_info('Configuration for Mac OS X ...')
elif "Linux" in check_os :
	os_used="Linux"
	mountrep="/mnt"
	print_info("Configuration for Linux ...")
else : 
	print "Not supported platform :("
	exit()
###################################################################################################################
###################################################################################################################
	
	
	
	


###################################################################################################################
def main():
	auth,proj,outputdir=initvar()
	menu(auth,proj,outputdir)
###################################################################################################################

###################################################################################################################
def initvar():
	#initialisation des donnees d'authentification
	authent=raw_input_in('>>IN> Have you got Windows credentials, [Y/N] ? >> ')
	while authent!="y" and authent!="Y" and authent!="n" and authent!="N"  :
		print_info( ">>WARN> Selection y, Y, n or N")
		authent=raw_input_in(">>IN> Have you got Windows credentials, [Y/N] ? >> ")
	
	if authent=="y" or authent=="Y" : 
		auth="1"
		if os.path.exists(smb_auth) : 
			print_log('>>LOG> File ' + smb_auth + ' exists')
			filesmb=open(smb_auth,'r')
			#print_log("######################################")
			c_filesmb=filesmb.readlines()
			print_log(c_filesmb[0].strip("\\tt\n"))
			#print_log(c_filesmb[1].strip("\\tt\n"))
			#print_log("######################################")
			filesmb.close()

		else : 
			print_log('>>LOG> File ' + smb_auth + ' does not exist, please to create it')
			exit()
		
		if os.path.exists(smb_auth2) : 
			print_log(">>LOG> File " + smb_auth2 + " exists")
			filesmb=open(smb_auth2,'r')
			#print_log("######################################")
			c_filesmb=filesmb.readlines()
			print_log(c_filesmb[0].strip("\\tt\n"))
			#print_log(c_filesmb[1].strip("\\tt\n"))
			print_log(c_filesmb[2].strip("\\tt\n"))
			#print_log("######################################")
			filesmb.close()
		else : 
			#print_log(">>LOG> File " + smb_auth2 + " does not exist, please to create it")
			exit()
		
	elif authent=="n" or authent=="N" : auth="0"
	
		
	#Creation ou utilisation de projet existants (init de la variable outputdir)
	project=raw_input_in('>>IN> Do you want load a special project, [Y/N] ? >> ')
	while project!="y" and project!="Y" and project!="n" and project!="N"  : 
		project=raw_input_in(">>IN> Do you want load a special project, [Y/N] ? >> ")
					 
	if project=="y" or project=="Y" :
		print_info( ">>INFO> AVAILABLE PROJECTS : ")
		res=os.popen('ls output/').read()
		print_ls(res)
		num_project=raw_input_in('>>IN> Choose your project >> ')
		outputdir="output/" + num_project
		proj="1"
	

	elif project=="n" or project=="N" :
		datestart=time.strftime('%y%m%d-%Hh%M',time.localtime())
		outputdir="output/" + datestart
		os.system ('mkdir ' + outputdir)
		proj="0"
		print_info( "\n################################################################################################")
		print_info( ">>INFO> PROJECT IN : [" + outputdir + "]")
		print_info( "################################################################################################\n")
	
	return auth,proj,outputdir
###################################################################################################################
###################################################################################################################
#MENU


###################################################################################################################
def menu(auth,proj,outputdir):
	#os.system ('clear')
	print_info("##############################################################################################")
	print_info2("                                  <<< MAIN : " + outputdir + ">>>                            ")
	if auth=="1" : print_info2("                                  <<< CRED : YES >>>                          ")
	else : print_info2("                                  <<< CRED : NO >>>")
	print_info("##############################################################################################")
	
	print_info( "\n1.  Find Windows DOMAINS")
	print_info( "2.  Find Windows Netbios WORKSTATIONS and SERVERS names (domain is required)")
	print_info( "3.  Convert Netbios name to IP address by DNS service (domain is required)")
	print_info( "3a. Convert Netbios name to IP address by NBNS service (domain or workgroup is required)")
	print_info( "4.  Identify UP HOST by network scan")
	print_info( "4a. Add/modify file containing UP HOSTS, manually")
	print_info( "5.  Generate SYSTEM INFORMATION (IP address is required)")
	print_info( "6.  Find NETWORK SHARES (IP address required)")
	print_info( "7.  Find SPECIAL FILES from network shares (IP address and network share are required) ")
	print_info( "8.  Find ACTIVE DIRECTORY servers from 5.")
	
	print_info("\n##################################<<<PLUS>>>##################################")
	
	print_info( "\n2b. Find Windows Netbios names of WORKSTATIONS and SERVERS (debug mode)")
	print_info( "3b. Find IP address from 2b")
	print_info( "3c. Check Netbios and SMB services (IP address is required)")
	
	print_info("\n##################################<<<TOOLS>>>##################################")
	
	print_info( "\n9.  Check the connection to a NETWORK SHARE")
	print_info( "10. Mount and unmount a NETWORK SHARE")
	print_info( "11. NEW or LOAD PROJECT")
	print_info( "12. Change Windows CREDENTIALS")
	print_info( "13. EXECUTE system command")
	print_info( "q.  QUIT")
	
	print_info("\n##############################################################################################")

	
	choice=raw_input_in('>>IN> Choose your operation >> ')

	if choice =="1" : option1(auth,proj,outputdir)
	elif choice =="2" : option2(auth,proj,outputdir)
	elif choice =="2b" : option2b(auth,proj,outputdir)
	elif choice =="3" : option3(auth,proj,outputdir)
	elif choice =="3a" : option3a(auth,proj,outputdir)
	elif choice =="3b" : option3b(auth,proj,outputdir)
	elif choice =="3c" : option3c(auth,proj,outputdir)
	elif choice =="4" : option4(auth,proj,outputdir)
	elif choice =="4a" : option4a(auth,proj,outputdir)
	elif choice =="5" : option5(auth,proj,outputdir)
	elif choice =="6" : option6(auth,proj,outputdir)
	elif choice =="7" : option7(auth,proj,outputdir)
	elif choice =="8" : option8(auth,proj,outputdir)
	elif choice =="9" : option9(auth,proj,outputdir)
	elif choice =="10" : option10(auth,proj,outputdir)
	elif choice =="11" : option11()
	elif choice =="12" : option12(auth,proj,outputdir)
	elif choice =="13" : option13(auth,proj,outputdir)
	elif choice =="q" : exit()
	else : 
		print_info( ">>INFO> Please to choose valid operation ...")
		menu(auth,proj,outputdir)
		


###################################################################################################################
#1:MAIN:Recherche des domaines
###################################################################################################################
def option1(auth,proj,outputdir):
	#recherche des domaines
	pre_search_domain(auth,proj,outputdir)
	#demande de realisation de l'option 2	
	next=raw_input_in('>>IN> Do you want to find machines [Y/N] ? >> ')
	if next == "y" or next == "Y" :	
		option2(auth,proj,outputdir)

	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################

###################################################################################################################
#1:Preparation aÂ  la recherche des domaines
###################################################################################################################
def pre_search_domain(auth,proj,outputdir):
		 # si le fichier de resultat existe dejà
		if os.path.exists(outputdir + "/D-all.txt")==True :
			erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')		
			if erase=="y" or erase=="Y" : search_domain(auth,proj,outputdir)
			elif erase=="n" or erase=="N" : menu(auth,proj,outputdir)
			
		# si le fichier n'existe pas -> lancement de la recherche des domaines
		else : search_domain(auth,proj,outputdir)

###################################################################################################################

###################################################################################################################
#1:Recherche des domaines disponibles
###################################################################################################################
def search_domain(auth,proj,outputdir):
	print_log( ">>LOG> SEARCHING FOR DOMAINS, BE PATIENT ...")
	#recherche et stockage des domaines identifies
	if auth=="0" : os.system ('smbtree -D -U "" -N >' + outputdir + "/D-all.txt")
	else : os.system ('smbtree -D -k -A ' + smb_auth + '>' + outputdir + "/D-all.txt")
	#affichage des domaines identifies	
	print_resgood( ">RES> FOUND DOMAINS >>")
	file=open(outputdir + "/D-all.txt",'r')
	domaines=file.readlines()
	for i in range(len(domaines)):
		domaine=domaines[i].strip("\n")
		print_resgood (domaine)
###################################################################################################################

###################################################################################################################
#2:MAIN:Recherche des machines d'un domaine
###################################################################################################################
def option2(auth,proj,outputdir):
	pre_search_machine(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)

###################################################################################################################
#2:Preparation de la recherche des machines d'un domaine
###################################################################################################################	
def pre_search_machine(auth,proj,outputdir):
	if os.path.exists(outputdir + "/D-all.txt")==True :
		print_info('>>INFO> The following lists of found domains (workgroups) are available >> ')
		read_file("/D-all.txt",outputdir)
	domain=raw_input_in('>>IN> Choose a domain >> ')
	if domain=="q" or domain=="Q" : menu(auth,proj,outputdir)
	if os.path.exists(outputdir + "/D-" + domain + "_M-all.txt")==True :
		choix=raw_input_in('Do you want to delete the previous results [Y/N] ? >> ')
		#demande d'ecrasement des resultats		
		if choix=="y" or choix=="Y" : search_machine(auth,domain,outputdir)
		else : menu(auth,proj,outputdir)
	else : search_machine(auth,domain,outputdir)
###################################################################################################################

###################################################################################################################
#2:Recherche de toutes les machines d'un domaine sepcifique
###################################################################################################################
def search_machine(auth,domain,outputdir):
	
	dom_mac_all= outputdir + "/D-all_M-all.txt"
	
 	#generation d un fichier contenant all domain et all machine
	if os.path.exists(dom_mac_all)==True :
		choix=raw_input_in('Do you want to generate a new file D-all_M-all.txt [Y/N] ? >> ')
		if choix=="y" or choix=="Y" : 
			print_log( ">>LOG> SEARCHING FOR WINDOWS NETBIOS NAMES, BE PATIENT ...")
			if auth=="0" : os.system ('smbtree -S -U "" -N >' + dom_mac_all)
			else : os.system ('smbtree -S -k -A ' + smb_auth + '>' + dom_mac_all) 
		
	else :
		print_log( ">>LOG> SEARCHING FOR WINDOWS NETBIOS NAMES, BE PATIENT ...")
		if auth=="0" : os.system ('smbtree -S -U "" -N >' + dom_mac_all)
		else : os.system ('smbtree -S -k -A ' + smb_auth + '>' + dom_mac_all)
	
	
	#recherche du domaine suivant pour creer un repere pour stopper la recherce
	#test si la recherche de tous les domaines et machines a ete realisee
	if os.path.exists(outputdir + "/D-all.txt")==False : search_domain(auth,proj,outputdir)
	#inscription des machines pour le domaine selectionne > D-<domain>_M-all.txt
	file_machine=outputdir + "/D-" + domain + "_M-all.txt"
	file_machine_str=outputdir + "/D-" + domain + "_M-all_tmp.txt"
	if os.path.exists(file_machine)==True : os.system('rm ' + file_machine)
		
	file=open(dom_mac_all,'r')
	b1=file.readlines()
	tag_dom="0"
	match_mac="\t"
	find="0"
	file=open(file_machine,'a')
	
	for i in range(len(b1)):
		b2=b1[i].strip("\n")
		if b2 == domain :
			tag_dom="1"
			continue
		if tag_dom=="1" :
			 #test si la ligne est une machine ou non 
			if match_mac in b2 :
				find="1"
				#filtrage des commentaires et des \\
				filtre_mac=re.compile('^\s\\\\\\\\(.+)\t+.*',re.IGNORECASE)
				b5=filtre_mac.search(b2)
				#recuperation du nom de machine filtree
				b6=b5.groups()[0]
				#suppression des espaces et tabulations
				b6=b6.replace(' ','')
				b6=b6.replace('\t','')
				#inscription dans le fichier de sortie
				file.write(b6)
				#ajout d'un saut de ligne
				file.write('\n')
			else : break
	if find=="1" :
		file.close()
		print_resgood( ">>RES> FOUND MACHINES FOR DOMAIN [" + domain + "] >>")
		print_resgood(open(file_machine).read())
		print_info( ">>INFO> RESULTS STORED IN [" + file_machine + "]")
	else : 
		print_resfail( ">>RES> NO FOUND MACHINE")
	return domain

###################################################################################################################		

###################################################################################################################		
#2b:MAIN:generation des infos de debuggage
###################################################################################################################		
def option2b(auth,proj,outputdir):
	dom_mac_all_verb= outputdir + "/D-all_M-all_verbose.txt"
	#generation d un fichier contenant all domain et all machine en mode verbose et aÂ  utiliser pour les domaines secondaires
	print_log( ">>LOG> SEARCHING FOR WINDOWS NETBIOS NAMES (verbose mode), BE PATIENT ...")
	if auth=="0" : os.system ('smbtree -S -e -d 5 -N >' + dom_mac_all_verb)
	else : os.system ('smbtree -S -e -d 5 -A ' + smb_auth + '>' + dom_mac_all_verb)
	print_info( ">>INFO> RESULTS STORED IN [" + dom_mac_all_verb + "]")
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################	

###################################################################################################################
#3:MAIN:Conversion des noms de machines du domaine principal en IP
###################################################################################################################
def option3(auth,proj,outputdir):
	pre_search_dns(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################

###################################################################################################################
#3:Preparation de la conversion des noms de machines en IP
##################################################################################################################	
def pre_search_dns(auth,proj,outputdir):
	tag_dns="nameserver"
	file_resolv="/etc/resolv.conf"
	file=open(file_resolv,'r')
	c1=file.readlines()
	
	for i in range(len(c1)):
		c2=c1[i].strip("\n")
		if tag_dns in c2 :
			print_info(">>INFO> For your information:")
			print_info("###1>")
			os.system('nslookup ' + c2.strip("nameserver"))
			print_info("###2>")
			os.system('cat /etc/resolv.conf')
 	dns_name=raw_input_in('>>IN> Choose DNS suffix of domain [Ex: FR.DOMAIN.COM, DOMAIN.local] >> ')
	if dns_name=="q" or dns_name=="Q" : menu(auth,proj,outputdir)
	use_prec=raw_input_in('>>IN> Do you want to view the files of Windows Netbios Name [Y/N] ? >> ')
	if use_prec=="y" or use_prec=="Y" : list_output("D-",outputdir)
	else : menu(auth,proj,outputdir)
	list_machine=raw_input_in('>>IN> Choose a file of Windows Netbios Name [Ex: D-DOMAIN_M-all.txt] >> ')
	filtre=re.compile('^D-(.+)\_.*',re.IGNORECASE)
	c4=filtre.search(list_machine)
	#recuperation du nom de domaine
	c5=c4.groups()[0]

	if os.path.exists(outputdir + "/N-" + c5 + "_M-all.txt")==True : 
		erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
		if erase=="y" or erase=="Y" : search_dns(dns_name,list_machine,outputdir,c5)
		elif erase=="n" or erase=="N" : menu(auth,proj,outputdir)
		else : menu(auth,proj,outputdir)
	else : search_dns(dns_name,list_machine,outputdir,c5)
###################################################################################################################

###################################################################################################################
#3:nslookup sur les noms de machine du domaine
###################################################################################################################
def search_dns(dns_name,list_machine,outputdir,c5):
	file_dom=outputdir + "/" + list_machine
	file_dom_ip=outputdir + "/N-" + c5 + "_M-all.txt"

	if os.path.exists(file_dom_ip)==True : os.system('rm ' + file_dom_ip)
		
	file=open(file_dom,'r')
	c3=file.readlines()
	
	file2=open(file_dom_ip,'a')
	
	print_log( ">>LOG> FROM WINDOWS NETBIOS NAMES TO IP ADDRESSES BY DNS, BE PATIENT >> ")
	j="0"
	for j in range(len(c3)):
		name_machine=c3[j].strip("\n")
		print_log( ">>LOG> CONVERSION N°:" + str(j))
		
		ip_res = os.popen('nslookup ' + name_machine + '.' + dns_name + '| grep Address | grep -v "#" | cut -d : -f 2').read()
		file2.write(ip_res)
	
	file.close()
	file2.close()
	print_resgood( ">>RES> THE FOLLOWING ADDRESSES HAVE BEEN IDENTIFIED >>")
	print open(file_dom_ip).read()	
	print_info( ">>INFO> RESULTS STORED IN [" + file_dom_ip + "]")

		
###################################################################################################################

###################################################################################################################
#3a:MAIN:Conversion des noms de machines du domaine principal en IP via netbios nbns
###################################################################################################################
def option3a(auth,proj,outputdir):
	pre_search_137(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################

###################################################################################################################
#3a:Preparation de la conversion des noms de machines en IP
##################################################################################################################	
def pre_search_137(auth,proj,outputdir):
	
	print_info('>>INFO> The following lists of Windows Netbios Name are available >> ')
	list_output("_M",outputdir)
	list_machine=raw_input_in('>>IN> Choose a file of Windows Netbios Name [Ex: D-DOMAIN_M-all.txt] >> ')
	filtre=re.compile('^D-(.+)\_.*',re.IGNORECASE)
	c4=filtre.search(list_machine)
	#recuperation du nom de domaine
	c5=c4.groups()[0]

	if os.path.exists(outputdir + "/N137-" + c5 + "_M-all.txt")==True : 
		erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
		if erase=="y" or erase=="Y" : search_137(list_machine,outputdir,c5)
		elif erase=="n" or erase=="N" : menu(auth,proj,outputdir)
		else : menu(auth,proj,outputdir)
	else : search_137(list_machine,outputdir,c5)
###################################################################################################################

###################################################################################################################
#3a:nbns sur les noms de machine du domaine
###################################################################################################################
def search_137(list_machine,outputdir,c5):
	file_dom=outputdir + "/" + list_machine
	file_dom_ip=outputdir + "/N137-" + c5 + "_M-all.txt"

	if os.path.exists(file_dom_ip)==True : os.system('rm ' + file_dom_ip)
		
	file=open(file_dom,'r')
	c3=file.readlines()
	
	file2=open(file_dom_ip,'a')
	
	print_log( ">>LOG> FROM WINDOWS NETBIOS NAMES TO IP ADDRESSES BY NBNS, BE PATIENT ... >> ")
	j="0"
	
	#
	for j in range(len(c3)):
		name_machine=c3[j].strip("\n")
		print_log( ">>LOG> CONVERSION N°:" + str(j))
		ip_res=os.popen('nmblookup ' + name_machine + '| grep "<00>" | cut -d " " -f 1').read()
		file2.write(ip_res)
	file.close()
	file2.close()
	print_resgood( ">>RES> THE FOLLOWING IP ADDRESSES ARE BEEN IDENTIFIED >>")
	print_resgood(open(file_dom_ip).read())	
	print_info( ">>INFO> RESULTS STORED IN [" + file_dom_ip + "]")		
###################################################################################################################

###################################################################################################################
#3b:MAIN:Identification des adresses IP depuis smbtree pour les domaines secondaires
###################################################################################################################
def option3b(auth,proj,outputdir):
	pre_search_smbtree_verbose(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################

###################################################################################################################
#3b:Preparation à  l'identification des adresses IP depuis smbtree
##################################################################################################################	
def pre_search_smbtree_verbose(auth,proj,outputdir):
	file_dom_all_verb=outputdir + "/D-all_M-all_verbose.txt"
	
	
	if os.path.exists(outputdir + "/D-all.txt")==True :
		use_prec=raw_input_in('>>IN> Do you want to view the found domains [Y/N] ? >> ')
		if use_prec=="y" or use_prec=="Y" : read_file("/D-all.txt",outputdir)
	
	dom=raw_input_in('>>IN> Choose a domain >> ')
	if os.path.exists(outputdir + "/N-" + dom + "_M-all_v.txt")==True : 
		erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
		if erase=="y" or erase=="Y" : search_ip(dom,outputdir)
		elif erase=="n" or erase=="N" : menu(auth,proj,outputdir)
	else : search_ip(dom,outputdir)
###################################################################################################################

###################################################################################################################
def search_ip(dom,outputdir):
	file_dom_all_verb=outputdir + "/D-all_M-all_verbose.txt"
	file_ip=outputdir + '/N-' + dom + '_M-all_v.txt'
	os.system('cat ' + file_dom_all_verb + '| grep "' + dom + '," | cut -d "," -f 2 >' + file_ip)
	print_resgood( ">>RES> THE FOLLOWING IP ADDRESSES ARE BEEN IDENTIFIED >>")
	print_resgood(open(file_ip).read())	
	print_info( ">>INFO> RESULTS STORED IN [" + file_ip + "]")
###################################################################################################################


###################################################################################################################
#3d:MAIN:Identification des machines disposant d'un acces SMB et Netbios
##################################################################################################################
def option3c(auth,proj,outputdir):
	pre_search_smb(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################

##################################################################################################################
#3d:Preparation a l'dentification des machines disposant d'un acces SMB
##################################################################################################################
def pre_search_smb(auth,proj,outputdir):
	#choix de la liste
	print_info( ">>INFO> The following lists of IP addresses are available >> ")		
	list_output("N-",outputdir)
	list_output("N137-",outputdir)
	list_sub_net=raw_input_in('>>IN> Choose a file of IP Addresses >> ')
	if list_sub_net=="q" or list_sub_net=="Q" : menu(auth,proj,outputdir)
	output_file=outputdir + "/" + list_sub_net.strip(".txt") + "_SMB.txt"
	if os.path.exists(output_file)==True : 	
		erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
		if erase=="n" or erase=="N" : pre_search_smb(auth,proj,outputdir)
		elif erase=="y" or erase=="Y" :
			os.system('rm ' + output_file)
			search_smb(list_sub_net,outputdir,output_file)

		else : menu(auth,proj,outputdir)
	else : search_smb(list_sub_net,outputdir,output_file) 
###################################################################################################################	

###################################################################################################################	
#3d:Identification des machines disposant d'un acces SMB et netbios
###################################################################################################################	
def search_smb(list_sub_net,outputdir,output_file):
	#scan nmap 
	os.system('nmap -sS -p 139,445' + ' -oN ' + outputdir + '/nmap -iL ' + outputdir + '/' + list_sub_net)
	#trie des infos et stockage  
	os.system('cat ' + outputdir + '/nmap | grep open -B 4 | grep -i nmap | cut -d \( -f 2 | cut -d \) -f 1 | cut -d " " -f 5 | grep -v initiated>'+ output_file)
	os.system('rm ' + outputdir + '/nmap')
	print_resgood( ">>RES> THE FOLLOWING ADDRESSES HAVE BEEN IDENTIFIED >>")
	print_resgood(open(output_file).read())
	print_info( ">>INFO> RESULTS STORED IN [" + output_file + "]")
###################################################################################################################	

###################################################################################################################
#4:MAIN:Generer une liste d'ADRESSES IP via un scan reseau
##################################################################################################################
def option4(auth,proj,outputdir):
	pre_search_option4(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################

##################################################################################################################
def pre_search_option4(auth,proj,outputdir):
	
	selected_scan=raw_input_in(">>IN>Scan ARP[1], Scan NBNS[2], Scan TCP 139/445[3] >> ")
	if selected_scan=="1" : pre_search_subnet_arp(auth,proj,outputdir)
	elif selected_scan=="2" : pre_search_subnet_nbns(auth,proj,outputdir)
	else : pre_search_subnet_tcp(auth,proj,outputdir)
	
###################################################################################################################


##################################################################################################################
#4/next:Preparation de "Generer une liste d'ADRESSES IP via un scan ARP"
##################################################################################################################
def pre_search_subnet_arp(auth,proj,outputdir):

	print_info("please to install arp-scan or launch command : sudo arp-scan -I en0 --localnet | cut -f 1")
				
	if os.path.exists(outputdir + "/N-localnet_M-all_ARP.txt")==True : 	
		erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
		if erase=="y" or erase=="Y" : search_subnet_arp(outputdir)
		elif erase=="n" or erase=="N" : menu(auth,proj,outputdir)
		else : menu(auth,proj,outputdir)
	else : search_subnet_arp(outputdir)
##################################################################################################################
	
##################################################################################################################
#4/next:Generer une liste d'ADRESSES IP via un scan ARP
#################################################################################################################
def search_subnet_arp(outputdir):
	file_ip=outputdir + "/N-localnet_M-all_ARP.txt"
	file=open(file_ip,'w')
	interf=raw_input_in(">>IN> Interface Name >> ")
	res=os.popen('arp-scan --localnet --interface ' + interf + '|grep -v Interface | grep -v packets | grep -v arp-scan |cut -d " " -f 1').read()
	print_log(res)
	filtre=re.compile('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',re.IGNORECASE)
	res2=filtre.findall(res)
	#recuperation du nom de domaine
	for ip in  res2:
		file.write(ip + '\n')
	file.close()	
	
	
	print_resgood( ">>RES> THE FOLLOWING ADDRESSES HAVE BEEN IDENTIFIED >>")
	print_resgood(open(file_ip).read())
	print_info( ">>INFO> RESULTS STORED IN [" + file_ip + "]")	
		
###################################################################################################################	

##################################################################################################################
#4/next:Preparation de "Generer une liste d'ADRESSES IP via un scan NBNS"
##################################################################################################################
def pre_search_subnet_nbns(auth,proj,outputdir):
	sub_net_base=raw_input_in(">>IN> Choose the base network address [Ex: 192.168.1] >> ")
	start=raw_input_in(">>IN> Choose the first byte [Ex: 1] >> ")
	stop=raw_input_in(">>IN> Choose the last byte [Ex: 254] >> ")
	sub_net=sub_net_base + "." + start + "-" + stop
	#if os.path.exists(outputdir + "/N-" + sub_net.replace("/", "-NET") + "_M-all.txt")==True :
		
	if os.path.exists(outputdir + "/N-" + sub_net + "_M-all_NBNS.txt")==True : 	
		erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
		if erase=="y" or erase=="Y" : search_subnet_nbns(sub_net_base,outputdir,start,stop)
		elif erase=="n" or erase=="N" : menu(auth,proj,outputdir)
		else : menu(auth,proj,outputdir)
	else : search_subnet_nbns(sub_net_base,outputdir,start,stop)
##################################################################################################################
	
##################################################################################################################
#4/next:Generer une liste d'ADRESSES IP via un scan NBNS
#################################################################################################################
def search_subnet_nbns(sub_net_base,outputdir,start,stop):
	sub_net=sub_net_base + "." + start + "-" + stop
	file_ip=outputdir + '/N-' + sub_net + "_M-all_NBNS.txt"
	#os.system ('nbtscan -r ' + sub_net + ' -s X | cut -d "X" -f 1 >' + file_ip)
	file=open(file_ip,'w')
	for i in range(int(start), int(stop)+1):
		ip= sub_net_base + "." + str(i)
		res=os.popen("nmblookup -A " + ip + "| grep -B 1 ACTIVE | grep up | cut -d ' ' -f 5 ").read()
		if res =="" : print_log (">>LOG> " + str(ip) + " >NOK")
		else : print_log (">>LOG> " + str(ip) + " >OK" )
		file.write(res)
	file.close()	
		
	print_resgood( ">>RES> THE FOLLOWING ADDRESSES HAVE BEEN FOUND >>")
	print_resgood(open(file_ip).read())
	print_info( ">>INFO> RESULTS STORED IN [" + file_ip + "]")		
		
###################################################################################################################	




##################################################################################################################
#4/next:Preparation de "Generer une liste d'ADRESSES IP via un scan TCP 139/445"
##################################################################################################################
def pre_search_subnet_tcp(auth,proj,outputdir):
	sub_net_base=raw_input_in(">>IN> Choose a network target [NMAP Format] >> ")
	sub_net_base_file=sub_net_base.replace('/','NET')
	if os.path.exists(outputdir + "/N-" + sub_net_base_file + "_M-all_SMB.txt")==True : 	
		erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
		if erase=="y" or erase=="Y" : search_subnet_tcp(sub_net_base,outputdir)
		elif erase=="n" or erase=="N" : menu(auth,proj,outputdir)
		else : menu(auth,proj,outputdir)
	else : search_subnet_tcp(sub_net_base,outputdir)
##################################################################################################################
	
##################################################################################################################
#4/next:Generer une liste d'ADRESSES IP via un scan TCP 139/445
#################################################################################################################
def search_subnet_tcp(sub_net_base,outputdir):
	sub_net_base_file=sub_net_base.replace('/','NET')

	file_ip=outputdir + '/N-' + sub_net_base_file + "_M-all_SMB.txt"
	print file_ip
	#scan nmap 
	os.system('nmap -sS -p 139,445 -P0' + ' -oN ' + outputdir + '/nmap ' + sub_net_base)
	#trie des infos et stockage  
	os.system('cat ' + outputdir + '/nmap | grep open -B 4 | grep -i nmap | cut -d \( -f 2 | cut -d \) -f 1 | cut -d " " -f 5 >'+ file_ip)
	os.system('rm ' + outputdir + '/nmap')	
	print_resgood( ">>RES> THE FOLLOWING ADDRESSES HAVE BEEN IDENTIFIED >>")
	print open(file_ip).read()
	print_info( ">>INFO> RESULTS STORED IN [" + file_ip + "]")	
		
###################################################################################################################	



###################################################################################################################
#4a:MAIN:Ajouter une liste d'adresse IP manuellement
##################################################################################################################
def option4a(auth,proj,outputdir):
	print_info( ">>INFO> The following lists of IP addresses are available >> ")		
	list_output("N-",outputdir)
	print_info("This option allows to add or modify file containing ip addresses (one ip per line)")
	name_file=raw_input_in("Type an existing <file name> or a new <file name> (N-<file name>_M-all.txt > ")
	name_file=outputdir + "/N-" + name_file + "_M-all.txt"
	os.system("vim " + name_file)
	menu(auth,proj,outputdir)
###################################################################################################################




###################################################################################################################	
#5:MAIN Recherche d'informations depuis une IP ou une liste d'adresses IP
###################################################################################################################
def option5(auth,proj,outputdir):
	pre_search_info_IP(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################	

###################################################################################################################	
#5:Preparation à la recherche d'informations depuis une IP ou une liste d'adresses IP
###################################################################################################################
def pre_search_info_IP(auth,proj,outputdir):
	# Choix du type de demande
	choix=raw_input_in('>>IN> Do you want to launch unitary test [Y/N] ? >> ')
	#travail depuis une adresse IP	
	if choix=="Y" or choix=="y" :
		# Saisie des parametres ip 
		ip=raw_input_in('>>IN> Choose an IP address >> ')
		if ip=="q" or ip=="Q" : menu(auth,proj,outputdir)
		output_file=outputdir + "/" + "IP-" + ip + "_Info.txt"
		
 		print_log( ">>LOG> SEARCHING FOR INFORMATIONS, BE PATIENT ...")
 		file2=open(output_file,'w')
		res=os.popen('nmblookup -A ' + ip).read()
		file2.write(res)
		file2.close()	

		#os.system('nbtscan ' + ip + '>>' + output_file)
		print_info( ">>INFO> RESULTS STORED IN [" + output_file + "]")
	
	#travail depuis une liste d'adresse IP
	elif choix=="n" or choix=="N" :
		print_info( ">>INFO> The following lists of IP addresses are available >> ")		
		list_output("N-",outputdir)
		list_output("N137-",outputdir)
		#list_output("_M",outputdir)

		list_sub_net=raw_input_in('>>IN> Choose a list of IP addresses >> ')
		if list_sub_net=="q" or list_sub_net=="Q" : menu(auth,proj,outputdir)
		output_file=outputdir + "/" + list_sub_net.strip(".txt") + "_Info.txt"	
		if os.path.exists(output_file)==True : 	
			erase=raw_input_in('>>IN> Do you want to delete the previous results [Y/N] ? >> ')
			if erase=="n" or erase=="N" : pre_search_info_IP(auth,proj,outputdir)
			elif erase=="y" or erase=="Y" :
				os.system('rm ' + output_file)
				search_info_IP(list_sub_net,outputdir,output_file)
			else : menu(auth,proj,outputdir)
		else : search_info_IP(list_sub_net,outputdir,output_file) 		
							
	#quitte la fonction
	else : menu(auth,proj,outputdir)
###################################################################################################################	
#5:Recherche d'informations depuis une liste d'adresse IP
#################################################################################################################
def search_info_IP(list_sub_net,outputdir,output_file):
	ip_file=outputdir + "/" + list_sub_net
	file=open(ip_file,'r')
	file2=open(output_file,'w')
	c_ip_file=file.readlines()
	print_log( ">>LOG> SEARCHING FOR INFORMATIONS, BE PATIENT ...")
	for i in range(len(c_ip_file)):
		ip=c_ip_file[i].strip("\n")
		print_log( ".")
		res=os.popen('nmblookup -A ' + ip).read()
		file2.write(res)

	file2.close()
	print_resgood( ">>RES> THE FOLLOWING ADDRESSES HAVE BEEN IDENTIFIED >>")
	print open(output_file).read()	
	print_info( ">>INFO> RESULTS STORED IN [" + output_file + "]")	
###################################################################################################################

###################################################################################################################
#6:MAIN:Recherche de partage reseau et de la possibilite d'y acceder
###################################################################################################################
def option6(auth,proj,outputdir):
	pre_search_share(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################	

###################################################################################################################	
#6:Preparation à la recherche de partage reseau et de la possibilite d'y acceder
###################################################################################################################
def pre_search_share(auth,proj,outputdir) :

	# Choix du type de demande
	choix=raw_input_in('>>IN> Do you want to launch unitary test [Y/N] ? >> ')
	#travail depuis une adresse IP	
	if choix=="Y" or choix=="y" :
		# Saisie des parametres ip 
		ip=raw_input_in('>>IN> Choose an IP address >> ')
		output_file_share=outputdir + "/IP-" + ip + "_S-all.txt"
		if os.path.exists(output_file_share)==True : 
			choix=raw_input_in('Do you want to delete the previous results [Y/N] ? >> ')
			if choix=="y" or choix=="Y" : 
				os.system('rm ' + output_file_share)
			elif choix=="Q" or choix=="q" : menu(auth,proj,outputdir)
			else : pre_search_share(auth,proj,outputdir) 
		search_share(auth,ip,outputdir,output_file_share)
					
		
	# travail depuis une liste d'adresse IP
	elif choix=="n" or choix=="N" :
		print_info( ">>INFO> The following lists of IP addresses are available >> ")		
		list_output("N-",outputdir)
		list_output("N137-",outputdir)
		
		ip_net=raw_input_in('Choose a list of IP addresses >> ')
		
		#creation du nom de fichier stockant les partages reseau (outputdir/N-DOMAIN_M-all_S-all.txt)
		output_file_share=outputdir + "/" + ip_net.strip(".txt") + "_S-all.txt"
		
			
		# verification de lexistence du fichier de resultat et confirmation de suppression
		if os.path.exists(output_file_share)==True : 
			choix=raw_input_in('Do you want to delete the previous results [Y/N] ? >> ')
			if choix=="y" or choix=="Y" : 
				os.system('rm ' + output_file_share)	
				#recherche et stockage des fichiers
				#lecture du fichier d'adresses IP 
				file=open(outputdir+ "/" + ip_net,'r')
				contenu=file.readlines()
				#Pour chaque adresse IP
				for i in range(len(contenu)):
					ip=contenu[i].strip("\t\n").strip(" ")
					#recherche des partages disponibles
					search_share(auth,ip,outputdir,output_file_share)			
				
			elif choix=="Q" or choix=="q" : menu(auth,proj,outputdir)
			else : pre_search_share(auth,proj,outputdir)
		else :
			#lecture du fichier d'adresses IP 
			file=open(outputdir+ "/" + ip_net,'r')
			contenu=file.readlines()
			#Pour chaque adresse IP
			for i in range(len(contenu)):
				ip=contenu[i].strip("\t\n").strip(" ")
				#recherche des partages disponibles
				search_share(auth,ip,outputdir,output_file_share)
				
	else : menu(auth,proj,outputdir)
	#suppression des traces
	# dans le cas où le demontage precedent n'a pu se faire, on force le demontage de tous les partages	
	os.system("umount " + mountrep + "/S-* > /dev/null 2>&1")
	os.system("rm " + outputdir + "/all-share_*")
	os.system("rm -rf " + mountrep + "/S-*")
	print_info (">>INFO> RESULTS STORED IN [" + output_file_share + "]")					
###################################################################################################################

###################################################################################################################
#6:Recherche des partages reseau pour une adresse Ip donnee
###################################################################################################################
def search_share(auth,ip,outputdir,output_file_share) :
	print_log( ">>TRACE>>" + ip)
	#creation du nom de fichier temporaire stockant tous les partages enumeres (outputdir/all-share_@ip.txt)
	f_all_share=outputdir + "/all-share_" + ip +".txt"
	file2=open(f_all_share,'w')

	#enumeration des partages de fichiers dans un fichier temporaire
	if auth=="0" : 
		####bug:arrive pas à ne récupérer que le nom de fichier sans les espaces derrière 
		#res = os.popen('smbclient -L ' + ip + ' -U anonymous -N | grep Disk').read()
		#filtre=re.compile('[\t]*(.+)',re.IGNORECASE)
		#resfiltre=filtre.findall(res)
		#for share in  resfiltre :
			#file2.write(share.strip('\*') + '\n')
		#file2.close()
		####
		###solution temporaire : ne gère pas les noms de partages avec espace
		res = os.popen('smbclient -L ' + ip + ' -U anonymous -N | grep Disk | cut -d " " -f 1').read()
		filtre=re.compile('[\t]*(.+)',re.IGNORECASE)
		resfiltre=filtre.findall(res)
		for share in  resfiltre :
			file2.write(share + '\n')
		file2.close()
	else : 
		####bug:arrive pas à ne récupérer que le nom de fichier sans les espaces derrière 
		#res = os.popen('smbclient -L ' + ip + ' -A ' + smb_auth + ' | grep Disk').read()
		#filtre=re.compile('[\t]*(.+)Disk',re.IGNORECASE)
		#resfiltre=filtre.findall(res)
		#for share in  resfiltre :
		#	file2.write(share.strip('\*') + '\n')
		#file2.close()
		####
		###solution temporaire : ne gère pas les noms de partages avec espace
		res = os.popen('smbclient -L ' + ip + ' -A ' + smb_auth + ' | grep Disk | cut -d " " -f 1').read()
		filtre=re.compile('[\t]*(.+)',re.IGNORECASE)
		resfiltre=filtre.findall(res)
		for share in  resfiltre :
			file2.write(share + '\n')
		file2.close()

	#analyse des resultats des partages identifies
	#si aucun resultat 
	if res=="" : print_resfail(">>RES > NO FOUND SHARE :(")
	else :
		file=open(f_all_share,'r')
		file3=open(output_file_share,'a')
		c_all_share=file.readlines()
		#pour chaque partage
		for j in range(len(c_all_share)):
			share=c_all_share[j].strip("\n")
			#verification de la possibilite de le monter et le demonte par la suite				
			mounted=vrfy_mount_share(auth,ip,share,outputdir)
			if mounted =="1" :
				#++
				#umount_share(ip,outputdir) 
				print_resgood(">>RES> NETWORK SHARE " + share + " OF " + ip + " IS MOUNTABLE ;)")
				#enregistrement de la possibilite de le monter
				detail_share= ip + ',' + share + '\n'
				file3.write(detail_share)
				#os.system('echo '+ ip + ',' + share + '>>' + output_file_share)
			else : print_resfail( ">>RES> NETWORK SHARE " + share + " OF " + ip + " IS UNMOUNTABLE :(")
		file3.close()
		
		#faire un string de file3
		strings_output_file_share=os.popen('strings ' + output_file_share).read()
		file3=open(output_file_share,'w')
		file3.write(strings_output_file_share)
		file3.close()
		
		file.close()
	
###################################################################################################################

###################################################################################################################
#7:MAIN:Preparation de la recherche des fichiers depuis une liste de partage reseau /IP
###################################################################################################################
def option7(auth, proj,outputdir):
	# Choix du type de demande
	choix=raw_input_in('>>IN> Do you want to launch unitary test [Y/N] ? >> ')
	#travail depuis une adresse IP	
	if choix=="Y" or choix=="y" :
		# Saisie des parametres ip et nom de partage
		chain="0"	
		ip=raw_input_in('>>IN> Choose an IP address >> ')
		share=raw_input_in('>>IN> Choose a name of network share >> ')
		file_type=raw_input_in('>>IN> Choose a file to find (all for *.*, *.xls, password*, …) >> ')
		choix_chain=raw_input_in('>>IN> Do you want to search a special chain into the file [Y/N] >> ')
		if choix_chain=="y" or choix_chain=="Y" : chain=raw_input_in('>>IN> Choose a special chain >> ')
		elif choix_chain=="n" or choix_chain=="N" : chain="nochain"
		elif choix_chain=="q" or choix_chain=="Q" : menu(auth, proj,outputdir)
		choix_down=raw_input_in('>>IN> Do you want to download found files [Y/N] >> ')
		mount_point=mountrep + "/S-" + ip 	

		# Montage du partage de fichier
		mounted=mount_share(auth,ip,share,outputdir)
		# Si le partage est monte
		if mounted =="1" :
			print_log( "\n>>LOG> NETWORK SHARE [" + share + "] OF [" + ip + "] IS MOUNTED ON [" + mount_point + "]")
			# recherche du fichier demande
			search_file(mount_point,share,file_type,outputdir,ip,chain,choix_down)
			#demontage du partage
			umount_share(ip,outputdir)
		# Si le partage na pas pu etre monte alors on quitte
		else : print_log( "\n>>LOG> NETWORK SHARE [" + share + "] OF [" + ip + "] IS UNMOUNTED")


	#travail depuis une liste
	elif choix=="N" or choix=="n" :
		#Saisie de la liste dadresse IP
		print_info( ">>INFO> The following lists of IP addresses/Network shares are available > ")
		os.system('ls ' + outputdir + ' | grep S-all.txt')
		choix_mac=raw_input_in('>>IN> Choose a list of IP addresses/Network shares >> ')
		if choix_mac=="q" or choix_mac=="Q" : menu(auth,proj,outputdir)
		file_mac=outputdir + "/" + choix_mac
		file_type=raw_input_in('>>IN> Choose a file to find (all for *.*, *.xls for Excel files, ...) >> ')
		choix_chain=raw_input_in('>>IN> Do you want to search a special chain in the file [Y/N] >> ')
		if choix_chain=="y" or choix_chain=="Y" : chain=raw_input_in('>>IN> Choose a special chain >> ')
		elif choix_chain=="n" or choix_chain=="N" : chain="nochain"
		elif choix_chain=="q" or choix_chain=="Q" : menu(auth, proj,outputdir)
		choix_down=raw_input_in('>>IN> Do you want to download found files [Y/N] >> ')
				
		file=open(file_mac,'r')
		res=file.readlines()
		for i in range(len(res)):
			lign=res[i].strip("\n")
			#recuperation du nom de machine filtree
			ip, share=lign.split(",")
			# Montage du partage de fichier
			mount_point=mountrep + "/S-" + ip
			mounted=mount_share(auth,ip,share,outputdir)
			# Si le partage est monte
			if mounted =="1" :
				print_log( "\n>>LOG> NETWORK SHARE [" + share + "] OF [" + ip + "] IS MOUNTED ON [" + mount_point + "]")
				# recherche du fichier demande
				search_file(mount_point,share,file_type,outputdir,ip,chain,choix_down)
				#demontage du partage
				umount_share(ip,outputdir)
			# Si le partage na pas pu etre monte alors on quitte
			else : print_log( ">>LOG> NETWORK SHARE [" + share + "] OF [" + ip + "] IS UNMOUNTED")
	
	#quitte la fonction
	else : menu(auth,proj,outputdir)	
	
	#suppression des points de montage
	os.system('rm -rf ' + mountrep + '/S-*')
	
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################
###cool
###################################################################################################################
#7:Recherche des fichiers depuis une liste de partage reseau /IP
###################################################################################################################
def search_file(mount_point,share,file_type,outputdir,ip,chain,choix_down):
	print_log( ">>LOG> SEARCHING FOR [" + file_type + "] FILES ON [" + mount_point + "] ...")
	# Creation des variables fichiers
	outputdown=outputdir + "/DOWNLOADED-FILES"
	outputdown2=outputdown + "/" + ip
	# _DFile pour stocker la liste des fichiers les fichiers téléchargés
	# _FFile pour stocker la liste des fichiers les fichiers trouvés
	if choix_down=="y" or choix_down=="Y": find_file=outputdir + "/IP-" + ip + "_DFile.txt"
	else : find_file=outputdir + "/IP-" + ip + "_FFile.txt"
	tag_end="FICHIERS"
	# Stockage du tag file
	tag_file="FILES [" + file_type.strip(".").strip("\*") + "] IN [" + share + "]"
	tag_file_chain="FILES [" + file_type.strip(".").strip("\*") + "] STORING [" + chain + "] IN [" + share + "]"
	
	#ouverture ou création du fichier de resultat
	file2=open(find_file,'a')
	
	# Si pas de demande de recherche de chaine
	if chain=="nochain":
		print_log( ">>LOG> SEARCHING FOR INFORMATIONS, BE PATIENT ...")
		start=os.popen('echo ' + tag_file + '\n').read()
		file2.write(start)
		if file_type=="all" : record=os.popen('find ' + mount_point + '\n').read()
		else: record=os.popen('find ' + mount_point + ' -type f -name ' + file_type + '\n').read()
		file2.write(record)
		print_info( ">>INFO> LIST OF FOUND FILES IS STORED IN [" + find_file + "]")
		file2.close()
		
		#faire un string de file2
		#strings_find_file=os.popen('strings ' + find_file).read()
		#file2=open(find_file,'w')
		#file2.write(strings_find_file)
		#file2.close()
		
		# Telechargement des eventuels fichiers identifies
		file=open(find_file,'r')
		res=file.readlines()
		tag="0"
		for i in range(len(res)):
			lign=res[i].strip("\n")
			if tag_file in lign :  # Si la ligne precedent les fichiers a telecharger a ete identifie
				tag="1"
				continue # on passe a la ligne suivante
			# Si plus aucun fichier a telecharger et identifier et recuperer les fichiers cibles
			if tag_end in lign and tag=="1" : break
			# Si des fichiers sont a telecharger
			if tag=="1" :
				# verification que le repertoire de stockage existe
				if os.path.exists(outputdown)==False : os.system('mkdir ' + outputdown)
				if os.path.exists(outputdown2)==False : os.system('mkdir ' + outputdown2)
				# copie des fichiers identifies si demandé
				if choix_down=="y" or choix_down=="Y":
					os.system('cp "' + lign + '" ' + outputdown2)
					print_resgood (">>RES> 1 NEW DOWNLOADED FILE [" + lign + "]")
				else : print_resgood (">>RES> 1 NEW FOUND FILE [" + lign + "]")
		if choix_down=="y" or choix_down=="Y": print_info( ">>INFO> COMPLETE DOWNLOAD - RESULTS STORED IN [" + outputdown2 + "]")



	# Si demande de recherche de chaine dans le fichier
	else :
		print_log( '>>LOG> SEARCHING FOR INFORMATIONS, BE PATIENT ...')
		start=os.popen('echo ' + tag_file_chain + '\n').read()
		file2.write(start)
		if file_type=="all" : record=os.popen('find ' + mount_point + ' -exec grep -Hnil "' + chain + '" {} \;' + '\n').read()
		else : record=os.popen('find ' + mount_point + ' -iname "' + file_type + '" -exec grep -Hnil "' + chain + '" {} \;' + '\n').read()
		file2.write(record)
		print_info( ">>INFO> LIST OF FOUND FILES IS STORED IN [" + find_file + "]")
		file2.close()
				
		#faire un string de file2 pour Mac :(
		#strings_find_file=os.popen('strings ' + find_file).read()
		#file2=open(find_file,'w')
		#file2.write(strings_find_file)
		#file2.close()
				
		file=open(find_file,'r')
		res=file.readlines()
		tag="0"
		for i in range(len(res)):
			lign=res[i].strip("\n")
			# Si 
			if tag_file_chain in lign :
				tag="1"
				continue
			# Si plus aucun fichier a telecharger et identifier et recuperer les fichiers cibles
			if tag_end in lign and tag=="1" : break
			# Si des fichiers sont a telecharger
			if tag=="1" :
				# verification que le repertoire de stockage existe
				if os.path.exists(outputdown)==False : os.system('mkdir ' + outputdown)
				if os.path.exists(outputdown2)==False : os.system('mkdir ' + outputdown2)
				# copie des fichiers identifies si demandé
				if choix_down=="y" or choix_down=="Y":
					os.system('cp "' + lign + '" ' + outputdown2)
					print_resgood( ">>RES> 1 NEW DOWNLOADED FILE [" + lign + "]")
				else : print_resgood (">>RES> 1 NEW FOUND FILE [" + lign + "]")
		if choix_down=="y" or choix_down=="Y": print_info( ">>INFO> COMPLETE DOWNLOAD - RESULTS STORED IN [" + outputdown2 + "]")
###################################################################################################################

###################################################################################################################		
#8:MAIN:Recherche de l'AD
###################################################################################################################
def option8(auth,proj,outputdir):
	pre_search_AD(auth,proj,outputdir)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################		
#8:Preparation à la recherche de l'AD
###################################################################################################################		
def pre_search_AD(auth,proj,outputdir):
	print_info(">>INFO> GENERATED INFORMATION FILES  >> ")
	print_info( ">>INFO> The following lists of information files are available >")
	os.system('ls ' + outputdir + ' | grep Info')
	file_info=raw_input_in(">>IN> Choose a information file >> ")
	if file_info=="q" or file_info=="Q" : menu(auth,proj,outputdir)
	file_DC=outputdir + "/" + file_info.strip("Info.txt") + "ADbyNBT.txt"
	file=open(file_DC,'w')
	
	#res=os.popen('cat ' + outputdir + "/" + file_info + '| grep "Domain Controllers" -B 10 | grep Host | cut -d ":" -f 1 | cut -d " " -f 6').read()
	res=os.popen('cat ' + outputdir + "/" + file_info + '|grep 1c -B 4 | grep status | cut -d " " -f 5').read()
	file.write(res)
	file.close()

	#os.system('cat ' + outputdir + "/" + file_info + '| grep "Domain Controllers" -B 10 | grep Host | cut -d ":" -f 1 | cut -d " " -f 6 >'+ file_DC)
	print_info(">>RES> IDENTIFIED AD SERVERS >> ")
	file=open(file_DC,'r')
	ipaddall=file.readlines()
	for i in range(len(ipaddall)):
		ipad=ipaddall[i].strip("\n")
		print (ipad)
	#print_info(os.system("cat " + file_DC))
	print_info( ">>RES> RESULTS STORED IN [" + file_DC + "]")
	file.close()

###################################################################################################################		

###################################################################################################################	
#9:MAIN:Test la possibilite de monter un partage reseau
###################################################################################################################
def option9(auth,proj,outputdir):
	#saisie des parametres ip et nom de partage	
	ip=raw_input_in('>>IN> Choose an IP address >> ')
	if ip=="q" or ip=="Q" : menu(auth,proj,outputdir)
	share=raw_input_in('>>IN> Choose a network share name >> ')
	if share=="q" or share=="Q" : menu(auth,proj,outputdir)
	#verification de la possibilite de montage
	mounted=vrfy_mount_share(auth,ip,share,outputdir)
	if mounted =="1" : print_resgood( ">>RES> NETWORK SHARE [" + share + "] OF [" + ip + "] CAN BE MOUNTED")
	else : print_resfail( ">>RES> IMPOSSIBLE TO MOUNT [" + share + "] OF [" + ip + "]")
	#suppression des points de montage
	os.system('rm -rf ' + mountrep + '/S-*')
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
###################################################################################################################
	
###################################################################################################################
#10:MAIN:Montage et demontage partage identifie
###################################################################################################################
def option10(auth,proj,outputdir):
	#saisie des parametres ip et nom de partage	
	ip=raw_input_in('>>IN> Choose an IP address >> ')
	if ip=="q" or ip=="Q" : menu(auth,proj,outputdir)
	share=raw_input_in('>>IN> Choose a network share name >> ')
	if share=="q" or share=="Q" : menu(auth,proj,outputdir)
	#verification de la possibilite de montage
	mounted=mount_share(auth,ip,share,outputdir)
	if mounted =="1" : print_log( ">>LOG> NETWORK SHARE [" + share + "] OF [" + ip + "] IS MOUNTED")
	else : print_log( ">>LOG> IMPOSSIBLE TO UNMOUNT [" + share + "] OF [" + ip + "]")
	choix=raw_input_in('>>IN> Do you want to unmount this network share [Y/N] ? >>')
	if choix=="y" or choix=="Y" : 
		umount_share(ip,outputdir)
		#suppression des points de montage
		os.system("rm -rf " + mountrep + "/S-"+ ip)
	raw_input_in(">>PRESS ANY KEY TO CONTINUE")
	menu(auth,proj,outputdir)
	
###################################################################################################################


###################################################################################################################
#montage d'un partage distant
###################################################################################################################
def mount_share(auth,ip,share,outputdir):
	###bug : mount_smbfs ne gère pas les espaces et accent dans le nom des partages
	#creation du point de montage
	mount_point=mountrep + "/S-" + ip
	if os.path.exists(mount_point)==False : os.system('mkdir ' + mount_point)
	#tente de monter le partage avec ou sans authentification
	#Sous Mac
	if os_used =="Mac":
		if auth=="0" : 
			os.system('mount_smbfs -d 777 -f 777 //:@' + ip + '/' + share.replace(" ","\ ") + ' ' + mount_point + ' > /dev/null 2>&1')
		else : 
			#recuperation des authentifiant
			filesmb=open(smb_auth2,'r')
			c_filesmb=filesmb.readlines()
			user_tmp=c_filesmb[0].strip("\t\t\n")
			title,user=user_tmp.split("=")
			#print user			
			passuser_tmp=c_filesmb[1].strip("\t\t\n")
			title,passuser=passuser_tmp.split("=")
			#print passuser
			domainuser_tmp=c_filesmb[2].strip("\t\t\n")
			title,domainuser=domainuser_tmp.split("=")
			#print domainuser
			
			filesmb.close()
			accent='"'
			#print "mount_smbfs -d 777 -f 777 //" + accent + domainuser + ";" + user + accent + ":" + accent + passuser + accent + "@" + ip + "/" + share + " " + mount_point
			os.system("mount_smbfs -d 777 -f 777 //" + accent + domainuser + ";" + user + accent + ":" + accent + passuser + accent + "@" + ip + "/" + share + " " + mount_point)
	#Sous Linux
	if os_used =="Linux":
		if auth=="0" : os.system('smbmount //' + ip + '/' + share.replace(" ","\ ") + ' ' + mount_point + ' -o guest > /dev/null 2>&1')
		else : 
			os.system('smbmount //' + ip + '/' + share + ' ' + mount_point + ' -o credentials=' + smb_auth2 + ' > /dev/null 2>&1')
	
	
	#verification que le partage est monte via la commande mount
	resmount=outputdir + '/' + 'resmount-' + ip
	os.system('mount >' + resmount)
	#analyse de la table de montage
	file=open(resmount,'r')
	res=file.readlines()
	for i in range(len(res)):
		lign=res[i]
		if mount_point in lign : 
			mounted="1"
			break
		else :  mounted="0"
	#suppression du point de montage et du fichier de resultat du montage si le montage nest pas possible
	if mounted=="0" :	
		os.system('rm -rf ' + mount_point)
		os.system('rm ' + resmount)
	#renvoi de l etat de montage
	return mounted
###################################################################################################################

###################################################################################################################
#demontage d'un partage distant
###################################################################################################################
def umount_share(ip,outputdir):
	mount_point=mountrep + "/S-" + ip
	resmount=outputdir + '/' + 'resmount-' + ip
	os.system('umount ' + mount_point)
	#++
	#os.system('rm -rf ' + mount_point)
	os.system('rm ' + resmount)
	
	print_log( ">>LOG> [" + mount_point + "] IS UNMOUNTED")
###################################################################################################################

###################################################################################################################
#verification de la possibilite de monter un partage reseau
###################################################################################################################
def vrfy_mount_share(auth,ip,share,outputdir):
	#creation du point de montage
	mount_point=mountrep + "/S-" + ip
	if os.path.exists(mount_point)==False : os.system('mkdir ' + mount_point)
	
	#Tente de monter le partage avec ou sans authentification
	#Infos : smbmount teste les ports 139 et 445 => pas besoin de spécifier les ports ... :)
	#Sous MAC OS
	#mount_smbfs -d 777 -f 777 //:@222.98.5.99/tmp /Volumes/test
	#mmount_smbfs -d 777 -f 777 //DEVOTEAM;user:password@222.98.5.99/tmp /Volumes/test
	if os_used =="Mac":
		if auth=="0" : os.system('mount_smbfs -d 777 -f 777 //:@' + ip + '/' + share + ' ' + mount_point + ' > /dev/null 2>&1')
		else : 
			#recuperation des authentifiant
			#recuperation des authentifiant
			filesmb=open(smb_auth2,'r')
			c_filesmb=filesmb.readlines()
			user_tmp=c_filesmb[0].strip("\t\t\n")
			title,user=user_tmp.split("=")
			#print user
			passuser_tmp=c_filesmb[1].strip("\t\t\n")
			title,passuser=passuser_tmp.split("=")
			#print passuser
			domainuser_tmp=c_filesmb[2].strip("\t\t\n")
			title,domainuser=domainuser_tmp.split("=")
			#print domainuser
			filesmb.close()
			accent='"'
			os.system("mount_smbfs -d 777 -f 777 //" + accent + domainuser + ";" + user + accent + ":" + accent + passuser + accent + "@" + ip + "/" + share + " " + mount_point + " > /dev/null 2>&1")
	#Sous Linux
	if os_used =="Linux":
		if auth=="0" : os.system('smbmount //' + ip + '/' + share + ' ' + mount_point + ' -o guest > /dev/null 2>&1')
		else : 
			os.system('smbmount //' + ip + '/' + share + ' ' + mount_point + ' -o credentials=' + smb_auth2 + ' > /dev/null 2>&1')
	
	#verification que le partage est monte via la commande mount
	resmount=outputdir + '/' + 'resmount-' + ip
	os.system('mount >' + resmount)
	#analyse de la table de montage
	mounted="0"
	file=open(resmount,'r')
	res=file.readlines()
	for i in range(len(res)):
		lign=res[i]
		if mount_point in lign : 
			mounted="1"
			umount_share(ip,outputdir)
			#on arrete de regarder les ligne suivantes
			break
		else : 
			mounted="0"
	#suppression du fichier de montage en cas de non utilisation de la fonction umount_share
	if mounted=="0": os.system('rm ' + resmount)	
	#renvoi de l etat de montage
	return mounted
###################################################################################################################

###################################################################################################################
#Affichage d'un fichier
###################################################################################################################

def read_file(input_file,outputdir):
	name_file=outputdir + input_file
	try:
		#print_info( ">>INFO> FILE STORES THE FOLLOWING DATA :" )
		file=open(name_file,'r')
		a1=file.readlines()
		for i in range(len(a1)):
			a2=a1[i].strip("\n")
			print_info(a2)
	except: 
		print_log( ">>WARN> NO RECORDED DATA")
###################################################################################################################

###################################################################################################################
#12:MAIN:changement des authentifiant
##################################################################################################################
###################################################################################################################	
def option12(auth,proj,outputdir):
	domain=raw_input_in('>>IN> Choose domain (. if you do not know it) > ')
	username=raw_input_in('>>IN> Choose username > ')
	password=raw_input_in('>>IN> Choose password > ')
	if os.path.exists(smb_auth) :
		filesmb=open(smb_auth,'w')
		filesmb.write('username=' + domain + '\\' + username + '\n')
		filesmb.write('password=' + password)
		filesmb.close()
		print_log('>>LOG> Credentials in ' + smb_auth + ' >')
		filesmb=open(smb_auth,'r')
		print_log("######################################")
		c_filesmb=filesmb.readlines()
		print_log(c_filesmb[0].strip("\\tt\n"))
		print_log(c_filesmb[1].strip("\\tt\n"))
		print_log("######################################")
		filesmb.close()
	else : print_log('>>LOG> File ' + smb_auth + ' does not exist, please to create it')
	if os.path.exists(smb_auth2) :
		filesmb=open(smb_auth2,'w')
		filesmb.write('username=' + username + '\n')
		filesmb.write('password=' + password + '\n')
		filesmb.write('workgroup=' + domain + '\n')
		filesmb.close()
		print_log('>>LOG> Credentials in ' + smb_auth2 + ' >')
		filesmb=open(smb_auth2,'r')
		print_log("######################################")
		c_filesmb=filesmb.readlines()
		print_log(c_filesmb[0].strip("\\tt\n"))
		print_log(c_filesmb[1].strip("\\tt\n"))
		print_log(c_filesmb[2].strip("\\tt\n"))
		print_log("######################################")
		filesmb.close()
	else : print_log('>>LOG> File ' + smb_auth2 + ' does not exist, please to create it')
	menu(auth,proj,outputdir)
###################################################################################################################




if __name__ == '__main__':
	main()
