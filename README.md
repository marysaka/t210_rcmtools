# t21_rcmtools

Some tools to interact with Tegra X1 RCM to handle download ane execution of images on the BPMP.

- ``tegrarcm`` and ``tegrasign``: Tools reproducing behaviours expected by NVIDIA LDK.
- ``tegradownload.py``: Download and execute on the BPMP a given binary in IRAM (at 0x40010000)
