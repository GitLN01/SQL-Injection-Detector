from tkinter import END

import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin


class sql_injection_detector:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    new_url = ""

    def __init__(self, url, message):
        global messagebox, vulnerable
        self.vulnerable = 0
        messagebox = message
        self.scan_sql_injection(url)

    def get_all_forms(self, url):
        soup = bs(self.s.get(url).content, "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        details = {}
        details["action"] = form.attrs.get("action", "").lower()
        details["method"] = form.attrs.get("method", "get").lower()

        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})

        details["inputs"] = inputs
        return details

    def is_vulnerable(self, response):
        errors = {
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "mysql_fetch_array() expects parameter",
            "ORA-01756: quoted string not properly terminated",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "Syntax error converting the nvarchar value",
            "org.hibernate.exception.SQLGrammarException",
            "Warning: pg_query(): Query failed",
            "Database error: syntax error"
        }

        for error in errors:
            if error in response.content.decode().lower():
                return True

        return False

    def scan_sql_injection(self, url):
        self.scan_url_for_sql_injection(url)
        if self.vulnerable < 2:
            self.scan_forms_for_sql_injection(url)


    def scan_url_for_sql_injection(self, url):
        global new_url, messagebox

        for c in "\"'":
            new_url = f"{url}{c}"
            message = '[!] Testiranje URL-a: '+ new_url + '\n\n'
            messagebox.insert(END, message)
            try:
                res = self.s.get(new_url)
            except:
                self.vulnerable = 2
                message = '[!] URL nije validan!'
                messagebox.insert(END, message)
                return

            if self.is_vulnerable(res):
                self.vulnerable = 1
                message = '[+] SQL Injection ranjivost otkrivena na linku:' + new_url + '\n\n'
                messagebox.insert(END, message)
                return

    def scan_forms_for_sql_injection(self, url):
        global new_url

        forms = self.get_all_forms(url)
        number_of_forms = len(forms)
        if(number_of_forms > 1):
            message = '[+] Detektovane ' + str(number_of_forms) + ' forme na URL-u: ' + str(url) + '.\n\n'
            messagebox.insert(END, message)
        else:
            message = '[+] Detektovana ' + str(number_of_forms) + ' forma na URL-u: ' + str(url) + '.\n\n'
            messagebox.insert(END, message)

        for form in forms:
            form_details = self.get_form_details(form)

            for c in "\"'":
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["value"] or input_tag["type"] == "hidden":
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        data[input_tag["name"]] = f"test{c}"

                url = urljoin(url, form_details["action"])

                if form_details["method"] == "post":
                    res = self.s.post(url, data=data)
                elif form_details["method"] == "get":
                    res = self.s.get(url, params=data)

                if self.is_vulnerable(res):
                    self.vulnerable = 1
                    message = '[+] SQL Injection ranjivost otkrivena na linku: ' + new_url + '\n\n'
                    messagebox.insert(END, message)
                    message = '[+] Forma:\n' + form_details
                    messagebox.insert(END, message)
                    break

    def is_site_vulnerable(self):
        return self.vulnerable