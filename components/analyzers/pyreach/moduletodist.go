package pyreach

import "strings"

// moduleToDistOverrides maps Python top-level module names to their
// canonical PyPI distribution names where the two differ. The lookup
// is case-sensitive on the module side because Python imports are
// (e.g. `from PIL import Image` is distinct from `from pil import …`).
// Distribution names are stored lowercase + hyphenated — the canonical
// form per PEP 503 normalization.
//
// Identity normalization (lowercase + underscore-to-hyphen) handles
// the common case (~70% of PyPI). This map covers well-known names
// that don't follow the identity rule. Missing an entry produces a
// false negative (the analyzer reports the package as unreachable
// when it actually was imported); the BFS through the dep graph
// usually catches it via a transitive edge from a correctly-mapped
// neighbor, but for top-level direct imports it is a real blind
// spot. PRs welcome.
var moduleToDistOverrides = map[string]string{
	// Common mismatches drawn from the most-downloaded PyPI packages.
	"PIL":                      "pillow",
	"bs4":                      "beautifulsoup4",
	"yaml":                     "pyyaml",
	"cv2":                      "opencv-python",
	"sklearn":                  "scikit-learn",
	"skimage":                  "scikit-image",
	"crypto":                   "pycryptodome",
	"Crypto":                   "pycryptodome",
	"OpenSSL":                  "pyopenssl",
	"git":                      "gitpython",
	"github":                   "pygithub",
	"jwt":                      "pyjwt",
	"dateutil":                 "python-dateutil",
	"dotenv":                   "python-dotenv",
	"magic":                    "python-magic",
	"slugify":                  "python-slugify",
	"serial":                   "pyserial",
	"usb":                      "pyusb",
	"docx":                     "python-docx",
	"pptx":                     "python-pptx",
	"google":                   "google-api-python-client",
	"googleapiclient":          "google-api-python-client",
	"googleapis_common_protos": "googleapis-common-protos",
	"grpc":                     "grpcio",
	"grpc_tools":               "grpcio-tools",
	"attr":                     "attrs",
	"attrs":                    "attrs",
	"win32api":                 "pywin32",
	"win32com":                 "pywin32",
	"pywintypes":               "pywin32",
	"Levenshtein":              "python-levenshtein",
	"MySQLdb":                  "mysqlclient",
	"psycopg2":                 "psycopg2-binary",
	"discord":                  "discord-py",
	"telegram":                 "python-telegram-bot",
	"jose":                     "python-jose",
	"socks":                    "pysocks",
	"OpenGL":                   "pyopengl",
	"snakemake":                "snakemake",
	"speech_recognition":       "speechrecognition",
	"prompt_toolkit":           "prompt-toolkit",
	"setuptools":               "setuptools",
	"pkg_resources":            "setuptools",
	"_pytest":                  "pytest",
	"IPython":                  "ipython",
	"backports":                "backports",
	"absl":                     "absl-py",
	"PyQt5":                    "pyqt5",
	"PyQt6":                    "pyqt6",
	"PySide2":                  "pyside2",
	"PySide6":                  "pyside6",
	"sqlalchemy":               "sqlalchemy",
	"flask_sqlalchemy":         "flask-sqlalchemy",
	"flask_login":              "flask-login",
	"flask_wtf":                "flask-wtf",
	"flask_migrate":            "flask-migrate",
	"flask_restful":            "flask-restful",
	"flask_cors":               "flask-cors",
	"djangorestframework":      "djangorestframework",
	"rest_framework":           "djangorestframework",
}

// stdlibModules is a conservative set of Python standard-library
// top-level modules. Imports of these are dropped from the runner's
// distribution set since stdlib is never a PyPI dependency. The list
// is not exhaustive (Python 3.12 has ~200 stdlib modules) but covers
// the most common ones; missing a stdlib module just produces a
// false-positive distribution name that the dep graph BFS will
// silently ignore (since no graph package will match), so this map
// is a performance optimization, not a correctness requirement.
var stdlibModules = map[string]struct{}{
	"abc": {}, "argparse": {}, "array": {}, "ast": {}, "asyncio": {},
	"base64": {}, "binascii": {}, "bisect": {}, "builtins": {}, "bz2": {},
	"calendar": {}, "cgi": {}, "cmath": {}, "cmd": {}, "codecs": {},
	"collections": {}, "colorsys": {}, "concurrent": {}, "configparser": {},
	"contextlib": {}, "contextvars": {}, "copy": {}, "copyreg": {}, "csv": {},
	"ctypes": {}, "curses": {}, "dataclasses": {}, "datetime": {}, "decimal": {},
	"difflib": {}, "dis": {}, "doctest": {}, "email": {}, "encodings": {},
	"enum": {}, "errno": {}, "faulthandler": {}, "fcntl": {}, "filecmp": {},
	"fileinput": {}, "fnmatch": {}, "fractions": {}, "ftplib": {}, "functools": {},
	"gc": {}, "getopt": {}, "getpass": {}, "gettext": {}, "glob": {}, "graphlib": {},
	"grp": {}, "gzip": {}, "hashlib": {}, "heapq": {}, "hmac": {}, "html": {},
	"http": {}, "imaplib": {}, "imghdr": {}, "imp": {}, "importlib": {}, "inspect": {},
	"io": {}, "ipaddress": {}, "itertools": {}, "json": {}, "keyword": {},
	"linecache": {}, "locale": {}, "logging": {}, "lzma": {}, "mailbox": {},
	"mailcap": {}, "marshal": {}, "math": {}, "mimetypes": {}, "mmap": {},
	"modulefinder": {}, "msilib": {}, "msvcrt": {}, "multiprocessing": {},
	"netrc": {}, "nis": {}, "nntplib": {}, "numbers": {}, "operator": {},
	"optparse": {}, "os": {}, "ossaudiodev": {}, "parser": {}, "pathlib": {},
	"pdb": {}, "pickle": {}, "pickletools": {}, "pipes": {}, "pkgutil": {},
	"platform": {}, "plistlib": {}, "poplib": {}, "posix": {}, "posixpath": {},
	"pprint": {}, "profile": {}, "pstats": {}, "pty": {}, "pwd": {}, "py_compile": {},
	"pyclbr": {}, "pydoc": {}, "queue": {}, "quopri": {}, "random": {}, "re": {},
	"readline": {}, "reprlib": {}, "resource": {}, "rlcompleter": {}, "runpy": {},
	"sched": {}, "secrets": {}, "select": {}, "selectors": {}, "shelve": {},
	"shlex": {}, "shutil": {}, "signal": {}, "site": {}, "smtpd": {}, "smtplib": {},
	"sndhdr": {}, "socket": {}, "socketserver": {}, "spwd": {}, "sqlite3": {},
	"ssl": {}, "stat": {}, "statistics": {}, "string": {}, "stringprep": {},
	"struct": {}, "subprocess": {}, "sunau": {}, "symtable": {}, "sys": {},
	"sysconfig": {}, "syslog": {}, "tabnanny": {}, "tarfile": {}, "telnetlib": {},
	"tempfile": {}, "termios": {}, "test": {}, "textwrap": {}, "threading": {},
	"time": {}, "timeit": {}, "tkinter": {}, "token": {}, "tokenize": {}, "tomllib": {},
	"trace": {}, "traceback": {}, "tracemalloc": {}, "tty": {}, "turtle": {},
	"types": {}, "typing": {}, "unicodedata": {}, "unittest": {}, "urllib": {},
	"uu": {}, "uuid": {}, "venv": {}, "warnings": {}, "wave": {}, "weakref": {},
	"webbrowser": {}, "winreg": {}, "winsound": {}, "wsgiref": {}, "xdrlib": {},
	"xml": {}, "xmlrpc": {}, "zipapp": {}, "zipfile": {}, "zipimport": {},
	"zlib": {}, "zoneinfo": {},
	// Special / pseudo modules:
	"__future__": {}, "__main__": {},
}

// isStdlibModule reports whether the given top-level module name is
// part of the Python standard library. Conservative — see stdlibModules.
func isStdlibModule(top string) bool {
	_, ok := stdlibModules[top]
	return ok
}

// moduleToDistribution maps a Python top-level module name to its
// canonical PyPI distribution name (lowercase, hyphenated). Returns
// "" for stdlib modules, relative imports, or anything that should
// be skipped.
//
// Order:
//  1. Skip stdlib.
//  2. Look up a static override (covers the well-known mismatches).
//  3. Identity normalize: lowercase + replace "_" with "-".
//
// Inputs that look like dotted module paths are reduced to the
// top-level segment first ("foo.bar.baz" -> "foo").
func moduleToDistribution(module string) string {
	module = strings.TrimSpace(module)
	if module == "" {
		return ""
	}
	// Drop relative-import dots (handled by caller, but defensive).
	module = strings.TrimLeft(module, ".")
	if module == "" {
		return ""
	}
	if i := strings.Index(module, "."); i >= 0 {
		module = module[:i]
	}
	if isStdlibModule(module) {
		return ""
	}
	if dist, ok := moduleToDistOverrides[module]; ok {
		return dist
	}
	return canonicalDistName(module)
}

// canonicalDistName normalizes a raw distribution name per PEP 503:
// lowercase and replace runs of [-_.] with a single "-".
func canonicalDistName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	out := make([]byte, 0, len(name))
	prevSep := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '-' || c == '_' || c == '.':
			if !prevSep && len(out) > 0 {
				out = append(out, '-')
			}
			prevSep = true
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
			prevSep = false
		default:
			out = append(out, c)
			prevSep = false
		}
	}
	// Trim trailing separator if any.
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}
