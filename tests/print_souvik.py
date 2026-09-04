"""Print 'souvik' 100 times and stream the output live to the Flushout dashboard."""

import time
import flushout

with flushout.stream(name="souvik-100"):
    for i in range(1, 101):
        print(f"[{i:03d}] souvik")
        time.sleep(0.1)  # small delay so you can watch it stream in real time
    print("\n🎉 Done! Printed souvik 100 times.")
