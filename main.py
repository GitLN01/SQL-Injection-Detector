from tkinter import CENTER

import sql_injection_detector
import tkinter
import customtkinter
from PIL import Image, ImageTk

# Primer sajta koji je ranjiv na SQL Injection: http://testphp.vulnweb.com/artists.php?artist=1

root = customtkinter.CTk()
root.resizable(False, False)
root.geometry("500x600")
root.title('Otkrivanje SQL ranjivosti uz pomoć Python alata')

image = Image.open("icon.png")
resized_image = image.resize((200, 150), Image.LANCZOS)
photo = ImageTk.PhotoImage(resized_image)

status_label = customtkinter.CTkLabel(master=root, text='Status:', font=("Arial", 22))
status_label.place(relx=0.02, rely=0.01)

status = customtkinter.CTkLabel(master=root, text='Nepoznato', font=("Arial", 22), text_color='#7d7d7d')
status.place(relx=0.18, rely=0.01)

entry = customtkinter.CTkEntry(root, placeholder_text="URL sajta za testiranje", width=350, height=30)
entry.place(relx=0.5, rely=0.45, anchor=CENTER)

image_label = tkinter.Label(root, image=photo)
image_label.place(relx=0.5, rely=0.25, anchor=CENTER)

label = customtkinter.CTkLabel(master=root, text='Ispis:')
label.place(relx=0.1, rely=0.59)

message = customtkinter.CTkTextbox(root, width=450, height=200, activate_scrollbars=True)
message.place(relx=0.5, rely=0.8, anchor=CENTER)

def test_sql_injection():
    message.delete('1.0', "end")
    url = entry.get()
    sql = sql_injection_detector.sql_injection_detector(url, message)
    sql_injection_status = sql.is_site_vulnerable()
    if(sql_injection_status == 1):
        status.configure(text='RANJIV', text_color='#a8131f')
    elif(sql_injection_status == 0):
        status.configure(text='NIJE RANJIV', text_color='#13a81d')
    else:
        status.configure(text='Nepoznato', text_color='#7d7d7d')

button = customtkinter.CTkButton(master = root, text="Testirajte sajt", command=test_sql_injection)
button.place(relx=0.5, rely=0.55, anchor=CENTER)

root.mainloop()