import streamlit as st
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from googlesearch import search
import requests
import time
import whois
import dns.resolver
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import ssl
import socket
import hashlib
import subprocess
import platform

# පිටුවේ සැකසුම්
st.set_page_config(page_title="Advanced OSINT Platform", page_icon="🕵️", layout="wide")


import streamlit as st

# පාස්වර්ඩ් ආරක්ෂාව
PASSWORD = "nadun" 

# සෙෂන් ස්ටේට් (Session State) එක භාවිතයෙන් පාස්වර්ඩ් එක නිවැරදි නම් සේව් කර තබා ගැනීම
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🔐 Access Control")
    password_input = st.text_input("Enter Access Password to use this Tool:", type="password")
    if password_input == PASSWORD:
        st.session_state.authenticated = True
        st.rerun() # පාස්වර්ඩ් එක නිවැරදි නම් වහාම පේජ් එක රීලෝඩ් කර පාස්වර්ඩ් බොක්ස් එක ඉවත් කරයි
    elif password_input:
        st.warning("⚠️ Please enter the correct password to use this tool.")
    st.stop() # පාස්වර්ඩ් එක දෙන තුරු යට ඇති ප්‍රධාන ටූල් එක පෙන්වීම වළක්වයි







# පැති මෙනුව
st.sidebar.title("🕵️ OSINT Platform")
st.sidebar.markdown("---")
menu = st.sidebar.radio("Select Investigation Module:", 
                        [
                         "📱 Phone Number Intelligence", 
                         "🌍 IP Address Tracking", 
                         "👤 Username Footprinting",
                         "📧 Email Intelligence",
                         "🌐 Domain/WHOIS Investigation",
                         "💻 MAC Address Tracker",
                         "🛡️ IP Threat & VPN Detection",
                         "📸 Image Forensics (EXIF)",
                         "🔒 SSL Certificate Intelligence",
                         "🕸️ Subdomain Scanner",
                         "🔑 Password & Hash Analyzer",
                         "🔌 Port Scanner",
                         "🛡️ HTTP Security Headers Check",
                         "🔗 URL Expander & Safe Link",
                         "🤖 Robots.txt & Sitemap Analyzer",
                         "📡 Network Ping Tool",
                         "💬 OSINT Assistant Chat",
                         "💬 OSINT Team Live Chat"
                        ])
st.sidebar.markdown("---")
st.sidebar.info("Developed for Advanced OSINT Investigations.")

# වාර්තා සෑදීමේ ශ්‍රිතය
def generate_report(title, data_dict):
    report = f"=== {title} ===\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    for key, value in data_dict.items():
        report += f"[*] {key}: {value}\n"
    report += "\n=== End of Report ==="
    return report

if menu == "📱 Phone Number Intelligence":
    st.title("📱 Global Phone Number Intelligence")
    
    # රටවල් ලැයිස්තුවක් ලබාදීම
    countries = {
        "Sri Lanka (+94)": "LK",
        "India (+91)": "IN",
        "United States (+1)": "US",
        "United Kingdom (+44)": "GB",
        "Australia (+61)": "AU",
        "Canada (+1)": "CA"
    }

    selected_country_name = st.selectbox("Select Country:", list(countries.keys()))
    selected_region = countries[selected_country_name]

    target_number = st.text_input("Enter Phone Number (Without country code or with it):")

    if st.button("Start Investigation", type="primary"):
        if target_number:
            try:
                # යූසර් තෝරාගත් රට හෝ + සමඟ දෙන ලද අංකය පදනම් කර ගනිමින් පාර්ස් කිරීම
                if target_number.startswith("+"):
                    parsed_number = phonenumbers.parse(target_number)
                else:
                    parsed_number = phonenumbers.parse(target_number, selected_region)

                if phonenumbers.is_valid_number(parsed_number):
                    st.success("✅ Valid Phone Number!")
                    
                    loc = geocoder.description_for_number(parsed_number, "en")
                    car = carrier.name_for_number(parsed_number, "en")
                    tz = timezone.time_zones_for_number(parsed_number)
                    
                    st.write(f"🌍 **Country/Location:** {loc}")
                    st.write(f"📡 **Carrier/Network:** {car}")
                    st.write(f"⏰ **Time Zone:** {', '.join(tz)}")
                else:
                    st.error("❌ Invalid phone number for the selected region.")
            except Exception as e:
                st.error(f"Error: {e}")



# ==========================================
# 2. IP ADDRESS TRACKING
# ==========================================
elif menu == "🌍 IP Address Tracking":
    st.title("🌍 IP Address Tracking")
    target_ip = st.text_input("Enter IP Address (e.g., 8.8.8.8):")
    if st.button("Track IP", type="primary"):
        if target_ip:
            try:
                res = requests.get(f"http://ip-api.com/json/{target_ip}").json()
                if res['status'] == 'success':
                    st.success("Active IP Address Found!")
                    st.write(f"**Country:** {res.get('country')} | **City:** {res.get('city')} | **ISP:** {res.get('isp')}")
                    st.markdown(f"[📍 **Google Maps**](https://www.google.com/maps/?q={res.get('lat')},{res.get('lon')})")
            except:
                st.error("Error fetching IP data.")

# ==========================================
# 3. USERNAME FOOTPRINTING
# ==========================================
elif menu == "👤 Username Footprinting":
    st.title("👤 Username Footprinting")
    target_user = st.text_input("Enter Username:")
    if st.button("Hunt Username", type="primary"):
        if target_user:
            platforms = {"GitHub": f"https://github.com/{target_user}", "Pinterest": f"https://www.pinterest.com/{target_user}/"}
            for platform, url in platforms.items():
                try:
                    res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
                    if res.status_code == 200:
                        st.success(f"✅ {platform}: Account Exists! 👉 {url}")
                except:
                    pass

# ==========================================
# 4. EMAIL INTELLIGENCE
# ==========================================
elif menu == "📧 Email Intelligence":
    st.title("📧 Email Intelligence")
    target_email = st.text_input("Enter Email Address:")
    if st.button("Analyze Email", type="primary"):
        if "@" in target_email:
            try:
                domain = target_email.split("@")[1]
                records = dns.resolver.resolve(domain, 'MX')
                st.success("✅ Mail Servers Found!")
                for mx in [str(r.exchange) for r in records]:
                    st.write(f"- `{mx}`")
            except:
                st.error("❌ No MX Records found.")

# ==========================================
# 5. DOMAIN / WHOIS INVESTIGATION
# ==========================================
elif menu == "🌐 Domain/WHOIS Investigation":
    st.title("🌐 Domain/WHOIS Investigation")
    target_domain = st.text_input("Enter Domain Name (e.g., example.com):")
    if st.button("WHOIS Lookup", type="primary"):
        try:
            w = whois.whois(target_domain)
            st.success("Domain Information Found!")
            st.write(f"**Registrar:** {w.registrar} | **Country:** {w.country}")
        except:
            st.error("Failed to retrieve WHOIS data.")

# ==========================================
# 6. MAC ADDRESS TRACKER
# ==========================================
elif menu == "💻 MAC Address Tracker":
    st.title("💻 MAC Address Tracker")
    target_mac = st.text_input("Enter MAC Address:")
    if st.button("Identify Vendor", type="primary"):
        try:
            res = requests.get(f"https://api.macvendors.com/{target_mac}")
            if res.status_code == 200:
                st.success(f"✅ Hardware Vendor: **{res.text}**")
            else:
                st.error("Vendor not found.")
        except:
            st.error("API Connection Error.")

# ==========================================
# 7. IP THREAT & VPN DETECTION
# ==========================================
elif menu == "🛡️ IP Threat & VPN Detection":
    st.title("🛡️ IP Threat & VPN Detection")
    target_ip = st.text_input("Enter IP Address:")
    if st.button("Analyze Threat Level", type="primary"):
        try:
            res = requests.get(f"http://ip-api.com/json/{target_ip}?fields=status,isp,mobile,proxy,hosting").json()
            if res.get('status') == 'success':
                if res.get('proxy'):
                    st.error("🚨 WARNING: VPN / Proxy / Tor Detected!")
                else:
                    st.success("✅ Clean IP (No Proxy Detected)")
                st.write(f"**Hosting/Datacenter:** {res.get('hosting')} | **Mobile:** {res.get('mobile')}")
        except:
            st.error("Error connecting to threat database.")

# ==========================================
# 8. IMAGE FORENSICS (EXIF)
# ==========================================
elif menu == "📸 Image Forensics (EXIF)":
    st.title("📸 Image Forensics (Metadata Extractor)")
    uploaded_file = st.file_uploader("Choose an image...", type=["jpg", "jpeg", "png"])
    if uploaded_file is not None:
        image = Image.open(uploaded_file)
        st.image(image, caption='Uploaded Image', use_column_width=True)
        exif_data = image._getexif()
        if exif_data:
            st.success("✅ Metadata Found!")
            for tag_id, data in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag in ["Make", "Model", "DateTimeOriginal"]:
                    st.write(f"**{tag}:** {data}")
        else:
            st.error("❌ No EXIF Metadata found.")

# ==========================================
# 9. SSL CERTIFICATE INTELLIGENCE
# ==========================================
elif menu == "🔒 SSL Certificate Intelligence":
    st.title("🔒 SSL Certificate Intelligence")
    target_site = st.text_input("Enter Domain (e.g., google.com):")
    if st.button("Inspect SSL Certificate", type="primary"):
        if target_site:
            clean_domain = target_site.replace("https://", "").replace("http://", "").split("/")[0]
            try:
                context = ssl.create_default_context()
                with socket.create_connection((clean_domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                        cert = ssock.getpeercert()
                        st.success("✅ SSL Certificate Retrieved Successfully!")
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        st.write(f"**Issuer Organization:** {issuer.get('organizationName', 'N/A')}")
                        subject = dict(x[0] for x in cert.get('subject', []))
                        st.write(f"**Subject Common Name:** {subject.get('commonName', 'N/A')}")
                        st.write(f"**Expires On:** {cert.get('notAfter')}")
            except Exception as e:
                st.error(f"❌ Failed to retrieve SSL certificate: {e}")

# ==========================================
# 10. SUBDOMAIN SCANNER
# ==========================================
elif menu == "🕸️ Subdomain Scanner":
    st.title("🕸️ Subdomain Scanner")
    target_domain = st.text_input("Enter Target Domain (e.g., dialog.lk):")
    if st.button("Scan Subdomains", type="primary"):
        if target_domain:
            try:
                res = requests.get(f"https://crt.sh/?q=%.{target_domain}&output=json", timeout=15)
                if res.status_code == 200:
                    subdomains = set(entry['name_value'] for entry in res.json() if "*" not in entry['name_value'])
                    st.success(f"✅ Found {len(subdomains)} Subdomains!")
                    for sub in sorted(list(subdomains))[:20]:
                        st.write(f"🔗 `{sub}`")
            except:
                st.error("Scanning failed.")

# ==========================================
# 11. PASSWORD & HASH ANALYZER
# ==========================================
elif menu == "🔑 Password & Hash Analyzer":
    st.title("🔑 Password Strength & Hash Analyzer")
    user_input = st.text_input("Enter Password or Text to Hash:", type="password")
    if st.button("Analyze & Hash", type="primary"):
        if user_input:
            md5_hash = hashlib.md5(user_input.encode()).hexdigest()
            sha256_hash = hashlib.sha256(user_input.encode()).hexdigest()
            st.subheader("🔐 Cryptographic Hashes")
            st.write(f"**MD5:** `{md5_hash}`")
            st.write(f"**SHA256:** `{sha256_hash}`")
            length = len(user_input)
            if length < 6:
                st.error("❌ Very Weak Password")
            elif length < 10:
                st.warning("⚠️ Moderate Strength")
            else:
                st.success("✅ Strong Password Structure")

# ==========================================
# 12. PORT SCANNER
# ==========================================
elif menu == "🔌 Port Scanner":
    st.title("🔌 Port Scanner (Defensive)")
    target_host = st.text_input("Enter Host/IP:")
    if st.button("Run Port Scan", type="primary"):
        if target_host:
            clean_host = target_host.replace("https://", "").replace("http://", "").split("/")[0]
            ports = [21, 22, 80, 443, 3306, 8080]
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    if s.connect_ex((clean_host, port)) == 0:
                        st.success(f"🟢 Port {port} is OPEN")
                    else:
                        st.error(f"🔴 Port {port} is CLOSED")
                    s.close()
                except:
                    pass

# ==========================================
# 13. HTTP SECURITY HEADERS CHECK
# ==========================================
elif menu == "🛡️ HTTP Security Headers Check":
    st.title("🛡️ HTTP Security Headers Check")
    target_url = st.text_input("Enter URL (e.g., https://google.com):")
    if st.button("Check Headers", type="primary"):
        if target_url:
            if not target_url.startswith("http"):
                target_url = "https://" + target_url
            try:
                res = requests.get(target_url, timeout=5)
                for header in ['Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security']:
                    if header in res.headers:
                        st.write(f"✅ **{header}:** Present")
                    else:
                        st.warning(f"⚠️ **{header}:** Missing")
            except Exception as e:
                st.error(f"Error: {e}")

# ==========================================
# 14. URL EXPANDER & SAFE LINK
# ==========================================
elif menu == "🔗 URL Expander & Safe Link":
    st.title("🔗 URL Expander & Safe Link Checker")
    st.write("Unshorten shortened URLs (bit.ly, tinyurl, etc.) safely without clicking them.")
    
    short_url = st.text_input("Enter Shortened URL (e.g., https://bit.ly/...):")
    if st.button("Expand URL", type="primary"):
        if short_url:
            if not short_url.startswith("http"):
                short_url = "https://" + short_url
            try:
                res = requests.head(short_url, allow_redirects=True, timeout=5)
                st.success("✅ Successfully Resolved Link!")
                st.write(f"**Final Destination URL:** `{res.url}`")
                st.write(f"**HTTP Status Code:** {res.status_code}")
            except Exception as e:
                st.error(f"Failed to expand URL: {e}")

# ==========================================
# 15. ROBOTS.TXT & SITEMAP ANALYZER
# ==========================================
elif menu == "🤖 Robots.txt & Sitemap Analyzer":
    st.title("🤖 Robots.txt & Sitemap Analyzer")
    st.write("Inspect hidden paths and sitemaps of a website.")
    
    target_domain = st.text_input("Enter Domain (e.g., example.com):")
    if st.button("Analyze Paths", type="primary"):
        if target_domain:
            clean_dom = target_domain.replace("https://", "").replace("http://", "").split("/")[0]
            base_url = f"https://{clean_dom}"
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("📄 robots.txt")
                try:
                    r = requests.get(f"{base_url}/robots.txt", timeout=5)
                    if r.status_code == 200:
                        st.code(r.text[:1000])
                    else:
                        st.warning("robots.txt not found.")
                except:
                    st.error("Error fetching robots.txt")
                    
            with col2:
                st.subheader("🗺️ sitemap.xml")
                try:
                    s = requests.get(f"{base_url}/sitemap.xml", timeout=5)
                    if s.status_code == 200:
                        st.success("✅ sitemap.xml exists!")
                    else:
                        st.warning("sitemap.xml not found.")
                except:
                    st.error("Error fetching sitemap")

# ==========================================
# 16. NETWORK PING TOOL
# ==========================================
elif menu == "📡 Network Ping Tool":
    st.title("📡 Network Ping & Latency Tool")
    st.write("Check server responsiveness and latency.")
    
    host = st.text_input("Enter Host/IP to Ping (e.g., 8.8.8.8):")
    if st.button("Run Ping", type="primary"):
        if host:
            clean_host = host.replace("https://", "").replace("http://", "").split("/")[0]
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", clean_host]
            try:
                with st.spinner("Pinging host..."):
                    output = subprocess.check_output(command, universal_newlines=True)
                    st.success("✅ Ping Completed Successfully!")
                    st.code(output)
            except Exception as e:
                st.error(f"Ping failed: {e}")

# ==========================================
# 17. OSINT ASSISTANT CHAT
# ==========================================
elif menu == "💬 OSINT Assistant Chat":
    st.title("💬 OSINT Assistant Chat")
    st.write("Interact with your local investigation log and assistant.")
    
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": "Hello! I am your OSINT Assistant. How can I help with your investigation today?"}
        ]

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("Type your investigation notes or ask a command..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            if "hello" in prompt.lower() or "hi" in prompt.lower():
                reply = "Hello! Ready for the next intelligence gathering task."
            elif "help" in prompt.lower():
                reply = "You can use this chat to log your findings, notes, or track targets while using the platform."
            else:
                reply = f"Logged your note/query: *'{prompt}'*. You can review your search steps here."
            
            st.markdown(reply)
            st.session_state.messages.append({"role": "assistant", "content": reply})

# ==========================================
# 18. OSINT TEAM LIVE CHAT
# ==========================================
elif menu == "💬 OSINT Team Live Chat":
    st.title("💬 OSINT Team Live Chat")
    st.write("Collaborate and chat live with other investigators using the platform.")
    
    if "team_messages" not in st.session_state:
        st.session_state.team_messages = [
            {"user": "System", "text": "Welcome to the OSINT Team Chatroom!"}
        ]

    username = st.text_input("Enter your Investigator Name:", value="Agent_007")

    st.markdown("---")
    
    chat_container = st.container()
    with chat_container:
        for msg in st.session_state.team_messages:
            st.markdown(f"**👤 {msg['user']}:** {msg['text']}")

    st.markdown("---")

    with st.form(key="chat_form", clear_on_submit=True):
        new_msg = st.text_input("Type your message...")
        submit_button = st.form_submit_button(label="Send Message")
        
        if submit_button and new_msg:
            st.session_state.team_messages.append({"user": username, "text": new_msg})
            st.rerun()
