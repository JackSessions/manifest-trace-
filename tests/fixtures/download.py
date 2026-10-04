"""Fetches the two real APKs used by the real-world tests. Not part of the product; run once before testing."""
import os
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = {
    "insecurebankv2.apk": "https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk",
    "clean-sample.apk": "https://f-droid.org/repo/com.ismartcoding.plain_10900064.apk",
}


def main() -> None:
    for name, url in FILES.items():
        path = os.path.join(HERE, name)
        if os.path.exists(path):
            print(f"already have {name}")
            continue
        print(f"downloading {name} ...")
        with urllib.request.urlopen(url, timeout=30) as r, open(path, "wb") as f:
            f.write(r.read())
        print(f"  {os.path.getsize(path):,} bytes")


if __name__ == "__main__":
    main()
