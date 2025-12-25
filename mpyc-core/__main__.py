import sys
import os
import shutil
import tarfile
import zipfile
import hashlib
import tempfile
from pathlib import Path
import requests
from tqdm import tqdm


class MIPError(Exception):
    """Base exception for MIP errors"""
    pass


class NetworkError(MIPError):
    """Network related errors"""
    pass


class PackageNotFoundError(MIPError):
    """Package not found on PyPI"""
    pass


class ExtractionError(MIPError):
    """File extraction errors"""
    pass


class ChecksumError(MIPError):
    """Checksum verification errors"""
    pass


class MIP:
    """MPyC Installer Package"""
    PYPI_API = "https://pypi.org/pypi/{package}/json"
    MAX_RETRIES = 3
    TIMEOUT = 30

    @staticmethod
    def log(msg, level="INFO"):
        """Print formatted log messages"""
        tags = {
            "INFO": "[INFO]",
            "OK": "[OK]",
            "ERR": "[ERROR]",
            "WARN": "[WARN]"
        }
        tag = tags.get(level, "[*]")
        print(f"{tag} {msg}")

    @staticmethod
    def validate_package_name(package: str) -> bool:
        """Validate package name format"""
        if not package or not isinstance(package, str):
            return False
        # Basic validation - alphanumeric, hyphens, underscores
        return all(c.isalnum() or c in '-_.' for c in package)

    @staticmethod
    def fetch_with_retry(url: str, retries: int = MAX_RETRIES, **kwargs) -> requests.Response:
        """Fetch URL with retry logic"""
        last_error = None
        
        for attempt in range(retries):
            try:
                response = requests.get(url, **kwargs)
                response.raise_for_status()
                return response
            except requests.Timeout as e:
                last_error = e
                MIP.log(f"Timeout on attempt {attempt + 1}/{retries}", "WARN")
            except requests.ConnectionError as e:
                last_error = e
                MIP.log(f"Connection error on attempt {attempt + 1}/{retries}", "WARN")
            except requests.RequestException as e:
                last_error = e
                if attempt < retries - 1:
                    MIP.log(f"Request failed, retrying... ({attempt + 1}/{retries})", "WARN")
                
        raise NetworkError(f"Failed after {retries} attempts: {last_error}")

    @staticmethod
    def install(package: str, version: str = None, exto: str = "Package") -> bool:
        """
        Install a package from PyPI with comprehensive error handling
        
        Args:
            package: Package name
            version: Specific version (optional)
            exto: Extract to directory
            
        Returns:
            bool: True if successful
        """
        temp_path = None
        
        try:
            # Validate inputs
            if not MIP.validate_package_name(package):
                MIP.log(f"Invalid package name: {package}", "ERR")
                return False

            # Create target directory
            try:
                Path(exto).mkdir(parents=True, exist_ok=True)
            except PermissionError:
                MIP.log(f"Permission denied: Cannot create directory {exto}", "ERR")
                return False
            except OSError as e:
                MIP.log(f"Failed to create directory {exto}: {e}", "ERR")
                return False
            
            # Fetch package metadata
            url = MIP.PYPI_API.format(package=package)
            MIP.log(f"Fetching metadata for '{package}'...")
            
            try:
                res = MIP.fetch_with_retry(url, timeout=MIP.TIMEOUT)
            except NetworkError as e:
                MIP.log(f"Network error: {e}", "ERR")
                return False

            if res.status_code == 404:
                raise PackageNotFoundError(f"Package '{package}' not found on PyPI")
            
            try:
                data = res.json()
            except ValueError as e:
                MIP.log(f"Invalid JSON response from PyPI: {e}", "ERR")
                return False

            # Determine version
            if version:
                ver = version
            else:
                try:
                    ver = data["info"]["version"]
                except KeyError:
                    MIP.log("Could not determine package version", "ERR")
                    return False

            # Get release files
            try:
                releases = data["releases"].get(ver)
            except (KeyError, AttributeError):
                MIP.log(f"Invalid releases data for {package}", "ERR")
                return False
                
            if not releases:
                MIP.log(f"Version {ver} not found for {package}", "ERR")
                MIP.log(f"Available versions: {', '.join(list(data['releases'].keys())[:10])}", "INFO")
                return False

            # Find suitable file
            file_info = next(
                (f for f in releases if f.get("filename", "").endswith((".tar.gz", ".zip", ".whl"))),
                None
            )
            if not file_info:
                MIP.log("No valid distribution file found (.tar.gz, .zip, .whl)", "ERR")
                return False

            file_url = file_info.get("url")
            filename = file_info.get("filename")
            
            if not file_url or not filename:
                MIP.log("Invalid file information in release", "ERR")
                return False

            MIP.log(f"Downloading {filename}...")

            # Download file
            try:
                temp_path = Path(tempfile.gettempdir()) / filename
                
                with MIP.fetch_with_retry(file_url, stream=True, timeout=60) as r:
                    total = int(r.headers.get('content-length', 0))
                    
                    with open(temp_path, "wb") as f, tqdm(
                        total=total, 
                        unit='B', 
                        unit_scale=True, 
                        desc=filename
                    ) as bar:
                        for chunk in r.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                bar.update(len(chunk))
                                
            except NetworkError as e:
                MIP.log(f"Download failed: {e}", "ERR")
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                return False
            except IOError as e:
                MIP.log(f"Failed to write file: {e}", "ERR")
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                return False

            MIP.log("Download complete", "OK")

            # Verify checksum
            digests = file_info.get("digests", {})
            if "sha256" in digests:
                try:
                    MIP.log("Verifying checksum...", "INFO")
                    sha = hashlib.sha256()
                    with open(temp_path, "rb") as f:
                        for chunk in iter(lambda: f.read(8192), b""):
                            sha.update(chunk)
                    
                    if sha.hexdigest() != digests["sha256"]:
                        raise ChecksumError("SHA256 checksum mismatch")
                    
                    MIP.log("Checksum verified", "OK")
                except ChecksumError as e:
                    MIP.log(str(e), "ERR")
                    temp_path.unlink(missing_ok=True)
                    return False
                except IOError as e:
                    MIP.log(f"Failed to verify checksum: {e}", "ERR")
                    temp_path.unlink(missing_ok=True)
                    return False

            # Extract package
            pkg_dir = Path(exto)
            try:
                if not MIP._extract(temp_path, pkg_dir):
                    raise ExtractionError("Extraction failed")
            except ExtractionError as e:
                MIP.log(str(e), "ERR")
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                return False

            # Cleanup
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)
            
            MIP.log(f"Successfully installed {package}=={ver} to {pkg_dir}", "OK")
            return True

        except PackageNotFoundError as e:
            MIP.log(str(e), "ERR")
            return False
        except NetworkError as e:
            MIP.log(f"Network error: {e}", "ERR")
            return False
        except Exception as e:
            MIP.log(f"Unexpected error: {type(e).__name__}: {e}", "ERR")
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink(missing_ok=True)
                except:
                    pass
            return False

    @staticmethod
    def _extract(filename: Path, target: Path) -> bool:
        """Extract and flatten package structure with error handling"""
        temp_dir = None
        
        try:
            if not filename.exists():
                MIP.log(f"File not found: {filename}", "ERR")
                return False

            # Validate file size
            file_size = filename.stat().st_size
            if file_size == 0:
                MIP.log("Downloaded file is empty", "ERR")
                return False

            target.mkdir(parents=True, exist_ok=True)
            temp_dir = target / "_temp_extract"
            temp_dir.mkdir(exist_ok=True)

            MIP.log("Extracting archive...", "INFO")

            # Extract archive
            try:
                if filename.suffixes[-2:] == [".tar", ".gz"] or str(filename).endswith('.tar.gz'):
                    with tarfile.open(filename, "r:gz") as tar:
                        # Security check: prevent path traversal
                        for member in tar.getmembers():
                            if member.name.startswith('/') or '..' in member.name:
                                raise ExtractionError(f"Unsafe file path in archive: {member.name}")
                        tar.extractall(temp_dir)
                        
                elif filename.suffix in [".zip", ".whl"]:
                    with zipfile.ZipFile(filename, "r") as zipf:
                        # Security check: prevent path traversal
                        for name in zipf.namelist():
                            if name.startswith('/') or '..' in name:
                                raise ExtractionError(f"Unsafe file path in archive: {name}")
                        zipf.extractall(temp_dir)
                else:
                    raise ExtractionError(f"Unsupported format: {filename}")
                    
            except tarfile.TarError as e:
                raise ExtractionError(f"Failed to extract tar.gz: {e}")
            except zipfile.BadZipFile as e:
                raise ExtractionError(f"Corrupted zip file: {e}")
            except Exception as e:
                raise ExtractionError(f"Extraction failed: {e}")

            # Flatten directory structure
            items = list(temp_dir.iterdir())
            if not items:
                raise ExtractionError("Archive is empty")

            try:
                if len(items) == 1 and items[0].is_dir():
                    # Single root folder - move contents up
                    inner = items[0]
                    for item in inner.iterdir():
                        dest = target / item.name
                        if item.is_dir():
                            MIP._move_dir(item, dest)
                        else:
                            item.replace(dest)
                else:
                    # Multiple items - move all
                    for item in items:
                        dest = target / item.name
                        if item.is_dir():
                            MIP._move_dir(item, dest)
                        else:
                            item.replace(dest)
            except (OSError, PermissionError) as e:
                raise ExtractionError(f"Failed to move files: {e}")

            # Cleanup temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            MIP.log("Extraction complete", "OK")
            return True

        except ExtractionError:
            raise
        except Exception as e:
            raise ExtractionError(f"Unexpected extraction error: {e}")
        finally:
            # Ensure temp directory is cleaned up
            if temp_dir and temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except:
                    pass

    @staticmethod
    def _move_dir(src: Path, dest: Path):
        """Move directory with overwrite and error handling"""
        try:
            if dest.exists():
                shutil.rmtree(dest)
            shutil.move(str(src), str(dest))
        except PermissionError as e:
            raise ExtractionError(f"Permission denied moving {src} to {dest}: {e}")
        except OSError as e:
            raise ExtractionError(f"Failed to move directory {src} to {dest}: {e}")


def copy_template():
    """Copy MPyC template to current directory with error handling"""
    src_dir = Path(__file__).parent / 'MPyC'
    dst_dir = Path.cwd() / "MPyC"
    
    try:
        if not src_dir.exists():
            print("[ERROR] MPyC template directory not found")
            print(f"[ERROR] Expected location: {src_dir}")
            return False
            
        if dst_dir.exists():
            response = input(f"[WARN] Directory '{dst_dir}' already exists. Overwrite? (y/N): ")
            if response.lower() != 'y':
                print("[INFO] Operation cancelled")
                return False
        
        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
        print("[OK] Template copied successfully")
        return True
        
    except PermissionError:
        print(f"[ERROR] Permission denied: Cannot write to {dst_dir}")
        return False
    except OSError as e:
        print(f"[ERROR] OS error: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error: {type(e).__name__}: {e}")
        return False


def get_arg(index, default=None):
    """Safely get command line argument"""
    try:
        return sys.argv[index] if len(sys.argv) > index else default
    except IndexError:
        return default


def main():
    """Main CLI entry point with comprehensive error handling"""
    try:
        current_dir = Path.cwd()
        pmp_flag = current_dir / "pmp.flag"
        package_mod = current_dir / "MPyC" / "Package"
        package_runtime = Path(__file__).parent.parent / "Runtime" / "Package"

        cmd1 = (get_arg(1) or "").lower()

        if cmd1 == "mod":
            cmd2 = (get_arg(2) or "").lower()

            if cmd2 == "install":
                pkg = get_arg(3)
                ver = get_arg(4)

                if not pmp_flag.exists():
                    print("[ERROR] Project not initialized (missing pmp.flag)")
                    print("[INFO] Run: mod init")
                    sys.exit(1)

                if not pkg:
                    print("[ERROR] Package name required")
                    print("[INFO] Usage: mod install <package> [version]")
                    sys.exit(1)

                success = MIP.install(pkg, version=ver, exto=str(package_mod))
                sys.exit(0 if success else 1)

            elif cmd2 == "init":
                try:
                    if pmp_flag.exists():
                        response = input("[WARN] Project already initialized. Reinitialize? (y/N): ")
                        if response.lower() != 'y':
                            print("[INFO] Operation cancelled")
                            sys.exit(0)
                    
                    with open("pmp.flag", "w") as f:
                        f.write("")
                    
                    if copy_template():
                        print("[OK] Project initialized successfully")
                        sys.exit(0)
                    else:
                        print("[ERROR] Initialization failed")
                        sys.exit(1)
                        
                except PermissionError:
                    print("[ERROR] Permission denied: Cannot create pmp.flag")
                    sys.exit(1)
                except IOError as e:
                    print(f"[ERROR] Failed to create pmp.flag: {e}")
                    sys.exit(1)

            else:
                print(f"[ERROR] Unknown command: mod {cmd2}")
                print("[INFO] Available commands:")
                print("  mod init              - Initialize project")
                print("  mod install <package> - Install package to project")
                sys.exit(1)

        elif cmd1 == "install":
            pkg = get_arg(2)
            ver = get_arg(3)

            if not pkg:
                print("[ERROR] Package name required")
                print("[INFO] Usage: install <package> [version]")
                sys.exit(1)

            success = MIP.install(pkg, version=ver, exto=str(package_runtime))
            sys.exit(0 if success else 1)
        
        elif cmd1 == "credit":
            print("Thanks to CWI, CNRI, BeOpen, Zope Corporation, the Python Software Foundation,")
            print("and a cast of thousands for supporting Python development.")
            print("See www.python.org for more information.")
            print("\nThanks to Azzam, ATE. See https://AzzTE.com for information.")
            sys.exit(0)

        elif cmd1:
            print(f"[ERROR] Unknown command: {cmd1}")
            print("\n[INFO] Usage:")
            print("  mod init              - Initialize project")
            print("  mod install <pkg>     - Install package to project")
            print("  install <pkg>         - Install package to runtime")
            print("  credit                - Show credits")
            sys.exit(1)
        else:
            print("Multi Python Compiler (MPyC)")
            print("\nCommands:")
            print("  mod init              - Initialize new project")
            print("  mod install <pkg>     - Install package to project")
            print("  install <pkg>         - Install package to runtime")
            print("  credit                - Show credits")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n[WARN] Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] Fatal error: {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()