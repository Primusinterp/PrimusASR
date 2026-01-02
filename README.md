# PrimusASR

PrimusASR is a helper script that i created in order to find ASR exclusions as low privilege user on a Windows endpoint. It parses the Windows Defender event logs for Event ID 5007 and extracts the ASR rules and their configuration state, along with any discovered exclusions. This method allows for an easy way of bypassing ASR rules such as ``01443614-cd74-433a-b99e-2ecdc07bfc25 - Block executable files from running unless they meet a prevalence, age, or trusted list criteria``. For further details about this method and other methods of bypassing this ASR rule, please check out my blog post [here](https://primusinterp.com/posts/WindowsASR/).

## Usage

```powershell
.\PrimusASR.ps1
```

## Output

The output is a table of the ASR rules and their configuration state along with any indentified Windows Defender or ASR exlusions.

<img width="1218" height="895" alt="image" src="https://github.com/user-attachments/assets/530ed81f-7623-4ce7-954d-99692196b922" />



## Disclaimer

This tool is designed for legitimate security testing and research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.
