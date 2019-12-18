import sys
import hashlib
import os
from tkinter import *
from tkinter import messagebox


root = Tk()
root.title("OneGuard")
root.geometry("650x550+350+100")
root.resizable(False, False)

top = Frame(root, height=150, bg='white')
top.pack(fill=X)
bottom = Frame(root, height=500, bg='#400082')
bottom.pack(fill=X)

top_image = PhotoImage(file='logo/logo.png')
top_image_label = Label(top, image=top_image, bg='white')
top_image_label.place(x=70, y=10)


def full_s_w():

  top_w=Toplevel()
  top_w.title("Full Scan")
  top_w.title("OneGuard")
  top_w.geometry("650x550+350+100")
  top_w.resizable(False, False)
  top = Frame(top_w, height=150, bg='#400082')
  top.pack(fill=X)
  bottom = Frame(top_w, height=500, bg='white')
  bottom.pack(fill=X)

  file_list = []
  full_scan_rootdir = "C:\\Users\\User\\Desktop\\Testing"

  def Scan():
    for subdir, dirs, files in os.walk(full_scan_rootdir):

      for file in files:
          filepath = subdir + os.sep + file
          if filepath.endswith(".exe") or filepath.endswith(".dll"):
              file_list.append(filepath)

    infected_list = []
    for f in file_list:
        virus_defs = open("VirusLIST.txt", "r")
        print("\nScanning: {}".format(f))
        hasher = hashlib.md5()
        try:
            with open(f, "rb") as file:
                try:
                    buf = file.read()
                    hasher.update(buf)
                    FILE_HASHED = hasher.hexdigest()
                    print("File md5 checksum: {}".format(FILE_HASHED))
                    for line in virus_defs:
                        if FILE_HASHED == line.strip():
                            infected_list.append(f)
                        else:
                            pass
                except Exception as e:
                    print("Could not read file | Error: {}".format(e))
        except:
            pass
    print("Infected files found: {}".format(infected_list))

    length = len(infected_list)

    if length == 0:

      messagebox.showinfo("Safe", "No Malware Detected",parent=top_w)
    else:

      messagebox.showinfo("Danger", "Malware Detected",parent=top_w)
      scroll = Scrollbar(bottom, orient=VERTICAL)

      listbox = Listbox(bottom, width=90, height=20)
      listbox.grid(row=0, column=0, padx=(30, 0))
      scroll.config(command=listbox.yview())
      listbox.config(yscrollcommand=scroll.set)

      for count, item in enumerate(infected_list):
        listbox.insert(count, item)

      scroll.grid(row=0, column=1, sticky=N+S)

      answer = messagebox.askquestion("Delete", "Want to delete malwares?",parent=top_w)

      if answer == 'yes':

        scroll = Scrollbar(bottom, orient=VERTICAL)
        listbox = Listbox(bottom, width=90, height=20)
        listbox.grid(row=0, column=0, padx=(30, 0))
        scroll.config(command=listbox.yview())
        listbox.config(yscrollcommand=scroll.set)

        for count, item in enumerate(infected_list):
          listbox.delete(count)
          os.remove(item)

        scroll.grid(row=0, column=1, sticky=N+S)

      else:
          pass

  fullButton = Button(top, width=10, height=2,
                      bg='white', text="Start Scan", font='verdana 14 bold', fg='#400082', command=Scan)

  fullButton.place(x=160, y=40)

  quickButton = Button(top, width=10, height=2,
                       bg='white', text="Back Home", font='verdana 14 bold', fg='#400082', command=top_w.destroy)
  quickButton.place(x=330, y=40)











#QUICK SCAN STARTS

def q_s_w():
  top_w = Toplevel()
  top_w.title("Full Scan")
  top_w.title("OneGuard")
  top_w.geometry("650x550+350+100")
  top_w.resizable(False, False)
  top = Frame(top_w, height=150, bg='#400082')
  top.pack(fill=X)
  bottom = Frame(top_w, height=500, bg='white')
  bottom.pack(fill=X)


  file_list2 = []
  quick_scan_rootdir = "C:\\Users\\User\\Desktop\\Testing"  # try small directory 


  def q_Scan():
    for subdir, dirs, files in os.walk(quick_scan_rootdir):
      for file in files:
          filepath = subdir + os.sep + file
          if filepath.endswith(".exe") or filepath.endswith(".dll"):
              file_list2.append(filepath)




    infected_list = []
    for f in file_list2:
        virus_defs = open("VirusLIST.txt", "r")
        print("\nScanning: {}".format(f))
        hasher = hashlib.md5()
        try:
            with open(f, "rb") as file:
                try:
                    buf = file.read()
                    hasher.update(buf)
                    FILE_HASHED = hasher.hexdigest()
                    print("File md5 checksum: {}".format(FILE_HASHED))
                    for line in virus_defs:
                        if FILE_HASHED == line.strip():
                            infected_list.append(f)
                        else:
                            pass
                except Exception as e:
                    print("Could not read file | Error: {}".format(e))
        except:
            pass
    print("Infected files found: {}".format(infected_list))

    length = len(infected_list)

    if length == 0:
      messagebox.showinfo("Safe", "No Malware Detected",parent=top_w)
    else:
      messagebox.showinfo("Danger", "Malware Detected",parent=top_w)
      scroll = Scrollbar(bottom, orient=VERTICAL)

      listbox = Listbox(bottom, width=90, height=20)
      listbox.grid(row=0, column=0, padx=(30, 0))
      scroll.config(command=listbox.yview())
      listbox.config(yscrollcommand=scroll.set)

      for count, item in enumerate(infected_list):
        listbox.insert(count, item)

      scroll.grid(row=0, column=1, sticky=N+S)

      answer = messagebox.askquestion("Delete", "Want to delete malwares?",parent=top_w)

      if answer == 'yes':

        scroll = Scrollbar(bottom, orient=VERTICAL)
        listbox = Listbox(bottom, width=90, height=20)
        listbox.grid(row=0, column=0, padx=(30, 0))
        scroll.config(command=listbox.yview())
        listbox.config(yscrollcommand=scroll.set)

        for count, item in enumerate(infected_list):
          listbox.delete(count)
          os.remove(item)

        scroll.grid(row=0, column=1, sticky=N+S)

      else:
          pass
  fullButton = Button(top, width=10, height=2,
                        bg='white', text="Start Scan", font='verdana 14 bold', fg='#400082', command=q_Scan)

  fullButton.place(x=160, y=40)

  quickButton = Button(top, width=10, height=2,
                       bg='white', text="Back Home", font='verdana 14 bold', fg='#400082', command=top_w.destroy)
  quickButton.place(x=330, y=40)





#QUICK SCAN FINISHED


    
  

fullButton = Button(bottom, width=10, height=2,
                    bg='white', text="Full Scan", font='verdana 14 bold', fg='#400082', command=full_s_w)
fullButton.place(x=160, y=50)

quickButton = Button(bottom, width=10, height=2,
                     bg='white', text="Quick Scan", font='verdana 14 bold', fg='#400082', command=q_s_w)
quickButton.place(x=330, y=50)


root.mainloop()
