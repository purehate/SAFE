# SAFE

---

## 📖 Description  
SAFE is a **non-destructive ransomware simulator**. Instead of encrypting real files, it creates a folder on your Desktop and fills it with fake “encrypted” files, tagged with common ransomware extensions.  

It’s designed for **purple team exercises, detection engineering, and EDR/SIEM validation** — with zero risk to production systems.  

Think of it as *Hackers* meets *Sneakers*:  

- Like Zero Cool said — *“There is no right and wrong, there’s only fun and boring.”* SAFE keeps it fun **and safe**.  
- As Cosmo reminded us in *Sneakers* — *“It’s all about who controls the information.”* SAFE gives you control of the simulation to see how your defenses respond.  

And yes, it’s got a TrustedSec vibe — because no tool is complete without some hacker-style ASCII art and a dash of Gibson green.  

---

## Features  
- Menu-driven interface  
- Choose a specific ransomware extension (e.g., `.locked`, `.encrypted`, `.crypt`, `.chaos`) or run **Kitchen Sink** mode for one of each  
- Generates realistic-looking “ciphertext” content (base64 garbage, not dangerous)  
- Optional ransom note to test detection of suspicious file drops  
- Safe cleanup option to remove the generated folder  

---

## Usage  

Run the tool with Python 3:

```bash
python3 SAFE.py
```

## Disclaimer--

- SAFE does not encrypt or modify any existing files. It only creates new dummy files inside a controlled folder. It is provided “as-is” for educational, research, and detection engineering purposes.

“Hack the planet. But do it safely.” – TrustedSec

