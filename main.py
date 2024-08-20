import sys
import argparse
import logging
from colorlog import ColoredFormatter
import os.path
from smtplib import SMTP, SMTPRecipientsRefused, SMTPSenderRefused, SMTPResponseException
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def parse_args():
    data = "This email is part of a security testing approved by the Security department. Thank you for your cooperation."
    parser = argparse.ArgumentParser()
    parser.add_argument('--targets', help="SMTP target server address or file containing SMTP servers list",
                        required=True)
    parser.add_argument('-p', '--port', help="SMTP target server port (default: 25)", type=int, default=25)
    parser.add_argument('--tester', help="Pentester email address", required=True)
    parser.add_argument('-t', '--toaddr', help="The recipient address (To)")
    parser.add_argument('-f', '--fromaddr', help="The sender address (From)")
    parser.add_argument('-d', '--data', help="The email content", default=data)
    parser.add_argument('-a', '--address', help="Addresses for VRFY command (single or file)")
    parser.add_argument('-s', '--subject', help="Email subject (default: 'SMTP Pentest')", default="SMTP Pentest")
    parser.add_argument('-i', '--internal', help="Perform internal spoofing test", action="store_true")
    parser.add_argument('-e', '--external', help="Perform external relay test", action="store_true")
    parser.add_argument('-v', '--vrfy', help="Perform user enumeration using VRFY command", action="store_true")
    parser.add_argument('--debug', help="Enable debug mode", action="store_true")
    return parser.parse_args()



def configure_logger():
    logger = logging.getLogger("SMTPTester")
    logger.setLevel(logging.INFO)
    log_colors = {
        'DEBUG': 'bold_red',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }
    formatter = ColoredFormatter("%(log_color)s[%(asctime)s] - %(message)s%(reset)s", datefmt='%d-%m-%Y %H:%M',
                                 log_colors=log_colors)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler("SMTPTester.log")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def external_test(smtp_targets, port, fromaddr, recipient, data, subject, debug, logger):
    data += "\nThis email is part of an external relay and/or spoofing test."

    for target in smtp_targets:
        logger.info(f"[*] Checking host {target}:{port} for external relay")
        try:
            if fromaddr and recipient:
                with SMTP(target, port) as smtp:
                    if debug:
                        smtp.set_debuglevel(1)
                    smtp.ehlo_or_helo_if_needed()

                    message = MIMEMultipart()
                    message["From"] = fromaddr
                    message["To"] = recipient
                    message["Subject"] = subject
                    message.attach(MIMEText(data, "plain"))

                    smtp.sendmail(fromaddr, recipient, message.as_string())
                    logger.critical(
                        f"[+] Server {target} appears to be VULNERABLE for external relay! Email sent FROM: {fromaddr} TO: {recipient}")
            else:
                logger.critical("[!] Problem with FROM and/or TO address!")
                sys.exit(1)
        except (SMTPRecipientsRefused, SMTPSenderRefused, SMTPResponseException) as e:
            logger.critical(f"[!] SMTP Error: {e}\n[-] Server: {target} NOT vulnerable!")
        except ConnectionRefusedError:
            logger.critical(f"[!] Connection refused by host {target}")
        except KeyboardInterrupt:
            logger.critical("[!] Stopping on user request...")
            sys.exit(1)
        except Exception as e:
            logger.critical(f"[!] Exception: {e}")
            sys.exit(1)


def internal_test(smtp_targets, port, fromaddr, toaddr, data, subject, debug, logger):
    data += "\nThis email is part of an internal relay and/or spoofing test."

    for target in smtp_targets:
        logger.info(f"[*] Checking host {target}:{port} for internal spoofing")
        try:
            if fromaddr and toaddr:
                from_domain = fromaddr.split('@').pop()
                to_domain = toaddr.split('@').pop()
                if from_domain != to_domain:
                    logger.error("[!] Sender and recipient domains don't match!")
                else:
                    with SMTP(target, port) as smtp:
                        if debug:
                            smtp.set_debuglevel(1)
                        smtp.ehlo_or_helo_if_needed()

                        message = MIMEText(data)
                        message['Subject'] = subject
                        message['From'] = fromaddr
                        message['To'] = toaddr

                        smtp.sendmail(fromaddr, toaddr, message.as_string())
                        logger.critical(
                            f"[+] Server {target} appears to be VULNERABLE for internal spoofing! Used FROM: {fromaddr}")
            else:
                logger.critical("[!] Problem with FROM and/or TO address!")
                sys.exit(1)
        except (SMTPRecipientsRefused, SMTPSenderRefused) as e:
            logger.critical(f"[!] SMTP Error: {e}\n[-] Server: {target} NOT vulnerable or TO address doesn't exist!")
        except ConnectionRefusedError:
            logger.critical(f"[!] Connection refused by host {target}")
        except KeyboardInterrupt:
            logger.critical("[!] Stopping on user request...")
            sys.exit(1)
        except Exception as e:
            logger.critical(f"[!] Exception: {e}")
            sys.exit(1)


def vrfy(smtp_targets, port, vrfy_addresses, debug, logger):
    for target in smtp_targets:
        logger.info(f"[*] Checking host {target}:{port} for user enumeration using VRFY")
        try:
            with SMTP(target, port) as smtp:
                for address in vrfy_addresses:
                    if debug:
                        smtp.set_debuglevel(1)
                    smtp.ehlo_or_helo_if_needed()
                    attempt = smtp.verify(address)

                    if attempt[0] in [250, 252]:
                        logger.info(f"[+] VRFY Success for address: {address} on server: {target}")
                    else:
                        logger.error(f"[!] VRFY failed for {address} on server: {target}")
        except KeyboardInterrupt:
            logger.critical("[!] Stopping on user request...")
            sys.exit(1)
        except Exception as e:
            logger.critical(f"[!] Exception: {e}")
            sys.exit(1)


def main():
    args = parse_args()
    logger = configure_logger()
    data = args.data + args.tester
    fake_address = "FakeDoNotExist@pentesting.pentesting"

    smtp_targets = open(args.targets).read().splitlines() if os.path.exists(args.targets) else [args.targets]

    if args.external:
        external_test(smtp_targets, args.port, args.fromaddr, args.tester, data, args.subject, args.debug, logger)
        external_test(smtp_targets, args.port, fake_address, args.tester, data, args.subject, args.debug, logger)
    elif args.internal:
        internal_test(smtp_targets, args.port, args.fromaddr, args.toaddr, data, args.subject, args.debug, logger)
    elif args.vrfy:
        if not args.address:
            logger.critical("[!] Missing the address parameter for VRFY")
            sys.exit(1)

        vrfy_addresses = open(args.address).read().splitlines() if os.path.exists(args.address) else [args.address]
        vrfy(smtp_targets, args.port, vrfy_addresses, args.debug, logger)
    else:
        external_test(smtp_targets, args.port, args.fromaddr, args.tester, data, args.subject, args.debug, logger)
        external_test(smtp_targets, args.port, fake_address, args.tester, data, args.subject, args.debug, logger)
        internal_test(smtp_targets, args.port, args.fromaddr, args.toaddr, data, args.subject, args.debug, logger)


if __name__ == '__main__':
    main()
