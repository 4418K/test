import os
import shutil
import sys
import random
from colorama import just_fix_windows_console

just_fix_windows_console()
# 定义随机颜色函数（使用ANSI 256色）
BRIGHT_COLORS = [
    # 标准高亮颜色
    8,  # 亮黑
    9,  # 亮红
    10,  # 亮绿
    11,  # 亮黄
    12,  # 亮蓝
    13,  # 亮品红
    14,  # 亮青
    15,  # 亮白

    # 来自 6x6x6 色立方体的鲜艳亮色
    196,  # 红色
    46,  # 绿色
    226,  # 黄色
    21,  # 蓝色
    201,  # 品红色
    51,  # 青色
    231,  # 白色

    # 其他一些漂亮的亮色
    207,  # 橙色
    219,  # 粉红色
    81,  # 青绿色
    129,  # 紫色
]


# 定义随机亮色函数
def random_color():
    return random.choice(BRIGHT_COLORS)


# 替换标准输出
class ColoredOutput:
    def __init__(self, orig_stdout):
        self.orig_stdout = orig_stdout

    def write(self, text):
        # 如果是提示行（比如包含">>> "），则不添加颜色
        if text.strip().startswith(">>> ") or text.strip().startswith("... "):
            self.orig_stdout.write(text)
        else:
            # 为每个字符添加随机颜色
            for char in text:
                if char == '\n' or char == ' ' or char == '\t':
                    # 空白字符不着色，直接输出
                    self.orig_stdout.write(char)
                else:
                    # 每个字符都获取新的随机颜色
                    color_code = random_color()
                    self.orig_stdout.write(f"\033[38;5;{color_code}m{char}\033[0m")

    def flush(self):
        self.orig_stdout.flush()


# 替换标准输出
sys.stdout = ColoredOutput(sys.stdout)
WATERMARK = """
    ·  ˚  ✦  ˚  ·  ˚  ✦  ·  ˚  ✦  ˚  ·
 ███████╗ ██╗  ██╗ ██╗ ██╗   ██╗ ██╗   ██╗
 ██╔════╝ ██║  ██║ ██║ ╚██╗ ██╔╝ ██║   ██║
 ███████╗ ███████║ ██║  ╚████╔╝  ██║   ██║
 ╚════██║ ██╔══██║ ██║   ╚██╔╝   ██║   ██║
 ███████║ ██║  ██║ ██║    ██║    ╚██████╔╝
 ╚══════╝ ╚═╝  ╚═╝ ╚═╝    ╚═╝     ╚═════╝ 
    ⚡  时  雨  T  o  o  l  ⚡
    ·  ˚  ✦  ˚  ·  ˚  ✦  ·  ˚  ✦  ˚  ·
"""

##############################################AA_Verification###########################################################
##############################################AA_Verification###########################################################
##############################################AA_Verification###########################################################
##############################################AA_Verification###########################################################
##############################################AA_Verification###########################################################
import http.client
import platform
import hashlib
import re
import os


def get_json_value(json, key):
    pattern = rf'"{key}"\s*:\s*(?:"([^"]*)"|(\d+\.?\d*)|(\w+))'
    match = re.search(pattern, json)

    if match:
        for g in match.groups():
            if g:
                return g
    return "None"


def get_machine_code():
    """
    生成本机唯一的 10 位纯数字机器码（简化稳定版）
    """

    system = platform.system()
    machine_id = None

    if system == "Windows":
        # Windows: 使用 MachineGuid（系统安装时生成，最稳定）
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            )
            machine_id, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
        except:
            pass

    if not machine_id:
        raise RuntimeError("无法获取机器标识")

    # MD5 哈希 -> 10位数字
    md5_hash = hashlib.md5(machine_id.encode("utf-8")).hexdigest()
    machine_code = str(int(md5_hash, 16) % (10 ** 10)).zfill(10)

    return machine_code


class Verification:
    def __init__(self):
        """初始化，获取机器码"""
        self.user = get_machine_code()
        # print(self.user)
        self.ver = "V1.2.1.1"

    def register(self):
        # print("机器码"+str(self.user))
        conn = http.client.HTTPSConnection("wlyz.cn")
        payload = ""
        headers = {}
        conn.request(
            "GET",
            "/api/member/register?appId=1555&nickname="
            + self.user
            + "&username="
            + self.user
            + "&password="
            + self.user
            + "&registerCode=&mac=&timestamp=&safeCode=&signature=",
            payload,
            headers,
        )
        res = conn.getresponse()
        data = res.read()
        # print(data.decode("utf-8"))

    def login(self):
        conn = http.client.HTTPSConnection("wlyz.cn")
        payload = ""
        headers = {}
        conn.request(
            "GET",
            "/api/member/login?appId=1555&username="
            + self.user
            + "&password="
            + self.user
            + "&mac=aaa&timestamp=&safeCode=&signature=",
            payload,
            headers,
        )
        res = conn.getresponse()
        data = res.read()
        # print(data.decode("utf-8"))
        return data.decode("utf-8")

    def Verify(self):
        result = self.login()
        # print(result)
        endtime = get_json_value(result, "endTime")
        test = get_json_value(result, "isVip")
        # print(test, self.user)
        if test != "true":
            print("查询会员状态失败\n请查看是否注册或是否到期")
            print("卡密购买网址：https://aceyun.cn/shop/KYY2M6E2/snxujo")
            print("永久只需28.8！")
            return self.recharge()
        else:
            print("验证成功，欢迎VIP用户！\n到期时间：" + endtime)
            return True

    def recharge(self):
        card = input("请输入卡密: ").strip()
        conn = http.client.HTTPSConnection("wlyz.cn")
        payload = ""
        headers = {}
        conn.request(
            "GET",
            "/api/member/recharge?appId=1555&username="
            + self.user
            + "&card="
            + card
            + "&token=&mac=&timestamp=&safeCode=&signature=",
            payload,
            headers,
        )
        res = conn.getresponse()
        data = res.read()
        # print(data.decode("utf-8"))
        result = get_json_value(data.decode("utf-8"), "msg")
        if result == "请重试":
            print("无法完成注册！")
            print("请检查网络是否有问题！")

        elif result == "充值码不存在":
            print("卡密不存在！\n请输入正确的卡密！")

        elif result == "充值成功":
            print("充值成功！")
            print("尽情使用工具吧！")
            return True

        elif result == "充值码已使用":
            print("卡密已经被使用过！")
            print("如果卡密还没到期直接登录辅助即可！")
            print("否则需要重新购买卡密！")

        elif result == "充值码长度应在16-32之间":
            print("请输入正确的卡密！")
        os.system('pause')
        return False

    def newver(self):
        conn = http.client.HTTPSConnection("wlyz.cn")
        payload = ''
        headers = {}
        conn.request("GET", "/api/expand/new-ver?appId=1555", payload, headers)
        res = conn.getresponse()
        data = res.read()
        # print(data.decode("utf-8"))
        result = get_json_value(data.decode("utf-8"), "msg")
        if result == "版本不存在":
            print("Unkonwn Error Occured!")
            return "exit"
        if (result != "ok"):
            print("无法获取工具版本！\n请检查网络设置！")
            return "exit"
        if get_json_value(data.decode("utf-8"), "num") != self.ver:
            print(f"检测到有新版本请更新！\n当前版本：{self.ver}\n最新版本：{get_json_value(data.decode("utf-8"), "num")}")
            print("最新版本下载地址：" + get_json_value(data.decode("utf-8"), "addr"))
            return "new"
        return "ok"


##############################################B_PackTool_quickbms#######################################################
##############################################B_PackTool_quickbms#######################################################
##############################################B_PackTool_quickbms#######################################################
##############################################B_PackTool_quickbms#######################################################
##############################################B_PackTool_quickbms#######################################################
import struct
import os
import argparse
import sys
import time

# ==============================================================================
# 导入压缩库
# ==============================================================================
import zlib_ng.zlib_ng as zlib

try:
    import zopfli.zlib

    HAS_ZOPFLI = True
except ImportError:
    HAS_ZOPFLI = False
    print("[Info] 'zopfli' module not found. Install it for best compression results.")

# ==============================================================================
# 配置与常量
# ==============================================================================
XOR_KEY = 0x79
MAGIC_SEARCH_1 = b"\x2E\x2E\x2F\x2E\x2E\x2F\x2E\x2E\x2F"  # ../../../
MAGIC_SEARCH_2 = b"\x57\x57\x56\x57\x57\x56\x57\x57\x56"  # XORed pattern


# ==============================================================================
# 基础工具类
# ==============================================================================
class BinaryStream:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.size = len(data)

    def read(self, size):
        if self.pos + size > self.size:
            ret = self.data[self.pos:]
            self.pos = self.size
            return ret
        ret = self.data[self.pos: self.pos + size]
        self.pos += size
        return ret

    def read_int32(self):
        b = self.read(4)
        return struct.unpack('<i', b)[0] if len(b) == 4 else 0

    def read_int64(self):
        b = self.read(8)
        return struct.unpack('<q', b)[0] if len(b) == 8 else 0

    def read_string(self):
        if self.pos + 4 > self.size: return ""
        length = self.read_int32()

        if length == 0: return ""
        if length > 10240 or length < -10240: return ""

        if length < 0:
            read_len = -length * 2
            if self.pos + read_len > self.size: return ""
            raw = self.read(read_len)
            return raw[:-2].decode('utf-16le', errors='replace')
        else:
            read_len = length
            if self.pos + read_len > self.size: return ""
            raw = self.read(read_len)
            return raw[:-1].decode('utf-8', errors='replace')


# ==============================================================================
# 核心引擎类
# ==============================================================================
class UE4PakEngine:
    def __init__(self, pak_path):
        self.pak_path = pak_path
        self.file_size = os.path.getsize(pak_path)
        self.entries_meta = []
        self.files_map = {}
        self.mount_point = ""
        self.is_encrypted = False
        self.index_offset = 0
        self.version = 0
        self.is_old_version = False

    def xor_data(self, data):
        return bytes([b ^ XOR_KEY for b in data])

    def _read_string_from_file(self, f):
        len_b = f.read(4)
        if len(len_b) < 4: return ""
        if self.is_encrypted: len_b = self.xor_data(len_b)
        length = struct.unpack('<i', len_b)[0]

        if length == 0: return ""
        if length > 10240 or length < -10240: return ""

        if length < 0:
            read_len = -length * 2
            raw = f.read(read_len)
            if self.is_encrypted: raw = self.xor_data(raw)
            return raw[:-2].decode('utf-16le', errors='replace')
        else:
            read_len = length
            raw = f.read(read_len)
            if self.is_encrypted: raw = self.xor_data(raw)
            return raw[:-1].decode('utf-8', errors='replace')

    def parse(self):
        print(f"[Analyze] Parsing {os.path.basename(self.pak_path)}...")
        with open(self.pak_path, 'rb') as f:
            f.seek(-0x2C, 2)
            _magic = f.read(4)
            self.version = struct.unpack('<i', f.read(4))[0]

            if self.version <= 7:
                self.is_old_version = True
                print(f"[Info] Version: {self.version} (OLD Layout)")
            else:
                self.is_old_version = False
                print(f"[Info] Version: {self.version} (NEW Layout)")

            scan_size = min(self.file_size, 20 * 1024 * 1024)
            f.seek(self.file_size - scan_size)
            buffer = f.read(scan_size)

            idx = buffer.rfind(MAGIC_SEARCH_1)
            if idx != -1:
                self.is_encrypted = False
            else:
                idx = buffer.rfind(MAGIC_SEARCH_2)
                if idx != -1:
                    self.is_encrypted = True
                    print("[Info] Detected Encryption (0x79)")
                else:
                    print("[Error] Failed to locate Index Offset.")
                    return False

            self.index_offset = (self.file_size - scan_size) + idx - 4
            f.seek(self.index_offset)

            self.mount_point = self._read_string_from_file(f)
            if self.mount_point.startswith("../../../"):
                self.mount_point = self.mount_point[9:]
            print(f"[Info] Mount Point: {self.mount_point}")

            cnt_b = f.read(4)
            if self.is_encrypted: cnt_b = self.xor_data(cnt_b)
            file_count = struct.unpack('<i', cnt_b)[0]
            print(f"[Info] File Count: {file_count}")

            if self.is_old_version:
                for i in range(file_count):
                    filename = self._read_string_from_file(f)
                    full_path = os.path.join(self.mount_point, filename).replace("\\", "/")
                    meta = self._read_entry_meta(f, debug_idx=i)
                    if not meta: break
                    self.entries_meta.append(meta)
                    self.files_map[full_path] = i
            else:
                print("[Info] Reading Entries...")
                for i in range(file_count):
                    meta = self._read_entry_meta(f, debug_idx=i)
                    if not meta: break
                    self.entries_meta.append(meta)

                f.read(8)
                if self.is_encrypted: f.read(1)

                curr = f.tell()
                dir_size = self.file_size - 0x2C - curr
                if dir_size > 0:
                    print(f"[Info] Parsing Directory Index ({dir_size} bytes)...")
                    dir_data = f.read(dir_size)
                    if self.is_encrypted: dir_data = self.xor_data(dir_data)
                    self._parse_directory_original(dir_data)
                else:
                    print("[Warning] No directory index found.")

            return True

    def _read_entry_meta(self, f, debug_idx=-1):
        raw = f.read(69)
        if len(raw) < 69: return None
        if self.is_encrypted: raw = self.xor_data(raw)

        br = BinaryStream(raw)
        e = {}
        e['hash'] = br.read(20)
        e['offset'] = br.read_int64()
        e['size'] = br.read_int64()
        e['zip'] = br.read_int32()
        e['zsize'] = br.read_int64()
        e['dummy'] = br.read(21)

        e['chunks'] = []
        if e['zip'] != 0:
            c_cnt_bytes = f.read(4)
            if self.is_encrypted: c_cnt_bytes = self.xor_data(c_cnt_bytes)
            chunk_count = struct.unpack('<i', c_cnt_bytes)[0]

            if chunk_count < 0 or chunk_count > 50000: return None

            for _ in range(chunk_count):
                c_raw = f.read(16)
                if self.is_encrypted: c_raw = self.xor_data(c_raw)
                c_off = struct.unpack('<q', c_raw[0:8])[0]
                c_end = struct.unpack('<q', c_raw[8:16])[0]
                e['chunks'].append({'start': c_off, 'end': c_end})

        tail = f.read(5)
        if self.is_encrypted: tail = self.xor_data(tail)
        e['max_chunk_size'] = struct.unpack('<i', tail[0:4])[0]
        e['is_encrypted'] = tail[4]

        if e['max_chunk_size'] == 0: e['max_chunk_size'] = 65536
        return e

    def _parse_directory_original(self, data):
        br = BinaryStream(data)
        try:
            if br.pos >= br.size: return
            num_dirs = br.read_int64()
            print(f"[Info] Found {num_dirs} directories.")
            if num_dirs > 200000 or num_dirs < 0: return

            for _ in range(num_dirs):
                dir_name = br.read_string()
                files_count = br.read_int64()
                full_dir = dir_name

                for _ in range(files_count):
                    file_name = br.read_string()
                    idx = br.read_int32()

                    full_path = f"{full_dir}/{file_name}".replace("\\", "/")
                    while "//" in full_path:
                        full_path = full_path.replace("//", "/")
                    if full_path.startswith("../../../"):
                        full_path = full_path[9:]
                    self.files_map[full_path] = idx
        except Exception as e:
            print(f"[Error] Directory parsing failed: {e}")

    def _compress_best(self, data, target_limit):
        """
        策略:
        1. 依次尝试 zlib level 1-9。
           - 一旦某一级别的压缩结果 <= target_limit，立即停止并返回（效率优先）。
        2. 如果 zlib 1-9 跑完仍未达标 (best_size > target_limit)，且支持 Zopfli，则尝试 Zopfli。
        3. 打印最终采用的策略名称和压缩比。
        """
        original_size = len(data)
        best_res = None
        best_size = sys.maxsize
        best_method = "None"

        # 辅助显示函数：用于显示正在进行的动作（会被覆盖）
        def show_progress(msg):
            sys.stdout.write(f"\r    {msg}")
            sys.stdout.flush()

        # 辅助显示函数：用于输出最终定案的结果（换行，不被覆盖）
        def print_final_decision(method, size):
            # 清除进度条
            sys.stdout.write("\r" + " " * 80 + "\r")

            ratio = (1 - size / original_size) * 100
            diff = size - target_limit

            # 状态标记：OK表示达标，LIMIT表示尽力了但没达标
            status = "OK" if size <= target_limit else f"LIMIT+{diff}"
            color_code = ""  # 这里可以加颜色代码，如果需要的话

            print(f"[{method}] Size: {size} ({ratio:.1f}%) -> {status}")

        # --- Phase 1: Zlib Level 1 - 9 ---
        for level in range(1, 10):
            # 只有在较高级别才显示进度，避免Level 1-3刷屏太快看不清
            if level > 3:
                show_progress(f"> [Testing] Zlib Level {level} (Current Best: {best_size})...")

            c = zlib.compress(data, level=level)
            c_len = len(c)

            # 更新全局最佳（以防万一后面没有更好的）
            if c_len < best_size:
                best_res = c
                best_size = c_len
                best_method = f"Zlib L{level}"

            # 【核心逻辑】如果当前级别已经满足目标大小，直接返回，不再尝试更高级别
            if c_len <= target_limit:
                print_final_decision(f"Zlib L{level}", c_len)
                return c

        # --- Phase 2: Zopfli (兜底) ---
        # 只有当 Zlib 1-9 还没把大小压到 target_limit 以下时，才启用 Zopfli
        if HAS_ZOPFLI and best_size > target_limit:
            show_progress(f"> [Zopfli] Analyzing... (Diff: {best_size - target_limit})")
            try:
                # numiterations=15 是个平衡点，追求极致可以设为 30 或 50
                c_zopfli = zopfli.zlib.compress(data, numiterations=15)
                if len(c_zopfli) < best_size:
                    best_res = c_zopfli
                    best_size = len(c_zopfli)
                    best_method = "Zopfli"
            except Exception:
                pass

        # --- End: 输出最终结果 ---
        # 无论是否达标，都返回找到的最小值
        print_final_decision(best_method, best_size)
        return best_res

    def extract(self, out_dir):
        print(f"Extracting {len(self.files_map)} files to {out_dir} ...")
        abs_out_dir = os.path.abspath(out_dir)
        with open(self.pak_path, 'rb') as f:
            for path, idx in self.files_map.items():
                if idx >= len(self.entries_meta): continue
                e = self.entries_meta[idx]
                safe_path = path.replace("\\", "/").lstrip("/")
                if not safe_path: continue
                dest = os.path.join(abs_out_dir, safe_path)
                if not os.path.abspath(dest).startswith(abs_out_dir): continue
                if os.path.isdir(dest): continue
                try:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, 'wb') as fo:
                        if len(e['chunks']) > 0:
                            for chunk in e['chunks']:
                                f.seek(chunk['start'])
                                size = chunk['end'] - chunk['start']
                                data = f.read(size)
                                if e['is_encrypted']: data = self.xor_data(data)
                                if e['zip'] != 0:
                                    try:
                                        data = zlib.decompress(data)
                                    except:
                                        pass
                                fo.write(data)
                        else:
                            f.seek(e['offset'])
                            read_size = e['zsize'] if e['zip'] != 0 else e['size']
                            data = f.read(read_size)
                            if e['is_encrypted']: data = self.xor_data(data)
                            if e['zip'] != 0:
                                try:
                                    data = zlib.decompress(data)
                                except:
                                    pass
                            fo.write(data)
                        print(f"Extracted: {safe_path}")
                except Exception as ex:
                    print(f"[Error] Failed to extract {safe_path}: {ex}")

    def reimport(self, in_dir):
        print(f"[Action] Patching from directory: {in_dir}")
        success_count = 0
        skip_count = 0

        files_to_process = []
        for root, dirs, files in os.walk(in_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, in_dir).replace("\\", "/").lstrip("/")
                files_to_process.append((rel_path, full_path))

        print(f"[Info] Found {len(files_to_process)} files to patch.")

        map_keys_lower = {k.lower(): k for k in self.files_map.keys()}

        with open(self.pak_path, 'r+b') as f:
            for rel_path, full_path in files_to_process:
                search_key = rel_path.lower()
                target_key = None

                if search_key in map_keys_lower:
                    target_key = map_keys_lower[search_key]
                if not target_key:
                    for mk, original_key in map_keys_lower.items():
                        if mk.endswith("/" + search_key) or mk == search_key:
                            target_key = original_key
                            break

                if not target_key:
                    print(f"[IGNORE] {rel_path} (Not in PAK)")
                    continue

                idx = self.files_map[target_key]
                e = self.entries_meta[idx]

                with open(full_path, 'rb') as fin:
                    new_data = fin.read()

                chunk_size = e['max_chunk_size']
                if chunk_size == 0: chunk_size = 65536

                new_slices = [new_data[i:i + chunk_size] for i in range(0, len(new_data), chunk_size)]
                orig_chunks = e['chunks']

                # A: 无 Chunk
                if len(orig_chunks) == 0:
                    phys_limit = e['zsize'] if e['zip'] != 0 else e['size']
                    blob = new_data
                    if e['zip'] != 0:
                        blob = self._compress_extreme(new_data, phys_limit)
                    if e['is_encrypted']: blob = self.xor_data(blob)

                    if len(blob) > phys_limit:
                        print(f"[FAIL] {rel_path} (Overflow: {len(blob)} > {phys_limit})")
                        skip_count += 1
                        continue

                    f.seek(e['offset'])
                    f.write(blob)
                    if len(blob) < phys_limit: f.write(b'\x00' * (phys_limit - len(blob)))
                    f.flush()
                    print(f"[OK] {rel_path}")
                    success_count += 1
                    continue

                # B: 有 Chunks
                if len(new_slices) > len(orig_chunks):
                    print(f"[FAIL] {rel_path} (Chunk Count Overflow)")
                    skip_count += 1
                    continue

                write_ops = []
                possible = True

                for i in range(len(orig_chunks)):
                    orig_chunk = orig_chunks[i]
                    phys_limit = orig_chunk['end'] - orig_chunk['start']

                    if i < len(new_slices):
                        raw_slice = new_slices[i]
                        final_data = raw_slice

                        if e['zip'] != 0:
                            final_data = self._compress_best(raw_slice, phys_limit)

                        enc_data = final_data
                        if e['is_encrypted']:
                            enc_data = self.xor_data(final_data)

                        if len(enc_data) > phys_limit:
                            print(f"[FAIL] {rel_path} (Chunk {i} Overflow: {len(enc_data)} > {phys_limit})")
                            possible = False
                            break

                        write_ops.append({
                            'offset': orig_chunk['start'],
                            'data': enc_data,
                            'padding': phys_limit - len(enc_data)
                        })
                    else:
                        write_ops.append({
                            'offset': orig_chunk['start'],
                            'data': b'',
                            'padding': phys_limit
                        })

                if possible:
                    for op in write_ops:
                        f.seek(op['offset'])
                        f.write(op['data'])
                        if op['padding'] > 0: f.write(b'\x00' * op['padding'])
                        f.flush()
                    print(f"[OK] {rel_path}")
                    success_count += 1
                else:
                    skip_count += 1

        print(f"\nDone. Updated: {success_count}, Skipped/Failed: {skip_count}")


###################################################C_STedit_new#########################################################
###################################################C_STedit_new#########################################################
###################################################C_STedit_new#########################################################
###################################################C_STedit_new#########################################################
###################################################C_STedit_new#########################################################
import os
import re
import shutil
import struct

# ==================== 基础路径定义 ====================
BASE_PATH = "./时雨自动/解包/"
BASE_PATH2 = "./时雨自动/制作区/"
PACK_PATH = "./时雨自动/打包/"


# ==================== 辅助工具函数 ====================

def get_subfolders(path):
    """获取指定路径下的子文件夹列表"""
    if not os.path.exists(path):
        return []
    return [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]


def find_file(directory, filename):
    for _, _, files in os.walk(directory):
        for file in files:
            if filename in file:
                return True
    return False


def find_battle_item(directory, filename="BattleItem.uexp"):
    for root, _, files in os.walk(directory):
        if filename in files:
            return os.path.relpath(os.path.join(root, filename), directory)
    return None


def copy_file_auto_create(source, dest):
    """复制文件，自动创建目录，目标存在则跳过"""
    if os.path.exists(dest):
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    return shutil.copy2(source, dest)


def write_to_destination(content, destination_file):
    """写入到目标文件"""
    try:
        os.makedirs(os.path.dirname(destination_file), exist_ok=True)
        with open(destination_file, 'wb') as dst:
            dst.write(content)
        return True
    except Exception as e:
        print(f"写入文件失败: {e}")
        return False


# ==================== 配置解析函数 ====================

def parse_config_file(config_file_path):
    """解析配置文件（增强格式兼容性）"""
    array = []
    invalid_lines = []
    separators = r'[, :=\s%-]+'  # 优化正则，合并连续分隔符

    try:
        with open(config_file_path, 'r', encoding='utf-8-sig') as file:
            for line_num, raw_line in enumerate(file, 1):
                # 去除注释和括号
                line = re.sub(r'#.*', '', raw_line).strip()
                line = re.sub(r'[()\[\]]', '', line).strip()

                if not line: continue

                parts = [p.strip() for p in re.split(separators, line) if p.strip()]

                if len(parts) == 2 and all(p.isdigit() for p in parts):
                    array.append([int(parts[0]), int(parts[1])])
                else:
                    invalid_lines.append(f"行{line_num}: {raw_line.strip()}")

        if invalid_lines:
            print("\n发现无效配置行：")
            for msg in invalid_lines: print(f"- {msg}")

        if not array: raise ValueError("无有效配置内容")
        return array

    except Exception as e:
        print(f"读取配置出错: {e}")
        return None


def parse_config_file2(config_file_path):
    """解析配置文件，提取[]内容"""
    array = []
    bracket_pattern = re.compile(r'\[(.*?)\]')

    try:
        with open(config_file_path, 'r', encoding='utf-8-sig') as file:
            for line_num, raw_line in enumerate(file, 1):
                line = re.sub(r'#.*', '', raw_line).strip()
                if not line: continue

                match = bracket_pattern.search(line)
                if match:
                    content = match.group(1).strip()
                    parts = [p.strip() for p in content.split(',') if p.strip()]
                    if parts:
                        array.append(parts)
                    else:
                        print(f"行{line_num}: 括号内无效 '{raw_line.strip()}'")
                else:
                    print(f"行{line_num}: 格式无效 '{raw_line.strip()}'")

        if not array: raise ValueError("无有效配置内容")
        return array

    except Exception as e:
        print(f"读取配置出错: {e}")
        return None


# ==================== 数据转换函数 ====================

def DEC_to_HEX(decimal_number, suffix=""):
    """将十进制转为小端序8位十六进制字符串"""
    # 使用 struct 或 int.to_bytes 简化逻辑
    # 8位十六进制 = 4字节
    hex_str = int(decimal_number).to_bytes(4, 'little').hex().upper()
    print(f"{decimal_number} 转换为：{hex_str + suffix}")
    return hex_str + suffix


def text_to_custom_format(text):
    """文本转自定义Hex格式（Little-Endian UTF-16 subset）"""
    result = []
    for char in text:
        cp = ord(char)
        # 范围检查
        if (32 <= cp <= 55295) or (57344 <= cp <= 65533):
            if char.isprintable() or cp == 32:
                # 转换为 UTF-16LE 的 Hex 字符串
                # 例如 'A' (0x0041) -> b'A\x00' -> '4100'
                hex_val = char.encode('utf-16le').hex().upper()
                result.append(hex_val)
            else:
                result.append("2000")  # 空格
        else:
            result.append("2000")
    return ''.join(result).strip()


def extract_feature_code(merged_data, search_sequence):
    """提取特征码"""
    seq_bytes = bytes.fromhex(search_sequence)
    index = merged_data.find(seq_bytes)
    if index == -1:
        print(f"未找到序列：{search_sequence}")
        return None
    # 检查是否越界
    if index + 4 + 2 <= len(merged_data):
        return merged_data[index + 4: index + 6].hex().upper()
    return None


def calculate_fixed_hex_from_suffix(suffix_hex, is_gun=False):
    """计算固定特征码"""
    # Suffix 是小端字符串，先转 int (视为大端读取逻辑，即 string -> bytes -> int big endian)
    # 原逻辑: suffix_hex[2:4] + suffix_hex[0:2] 其实就是把 "CDAB" 变成了 "ABCD"
    val = int.from_bytes(bytes.fromhex(suffix_hex), 'little')
    offset = 0x0D if is_gun else 0x11
    val += offset
    # 转回小端 Hex 字符串
    return val.to_bytes(2, 'little').hex().upper()


def calculate_new_suffix(fixed_hex, is_gun=False):
    """计算备用后缀"""
    val = int.from_bytes(bytes.fromhex(fixed_hex), 'little')
    offset = 0x02 if is_gun else 0x06
    val -= offset
    return val.to_bytes(2, 'little').hex().upper()


def calc(first_feature_code, offset):
    """通用偏移计算"""
    val = int.from_bytes(bytes.fromhex(first_feature_code), 'little')
    val += offset
    return val.to_bytes(2, 'little').hex().upper()


# ==================== 核心修改功能 ====================

# ***************** 功能1 & 2: 贴图修改 *****************
def modify_file_hex(file_contents, A, B, fixed_hex, suffix_hex):
    search_seq1 = bytes.fromhex(A + suffix_hex)
    search_seq2 = bytes.fromhex(B + suffix_hex)
    fixed_bytes = bytes.fromhex(fixed_hex)

    idx1 = file_contents.find(search_seq1)
    idx2 = file_contents.find(search_seq2)
    if idx1 == -1 or idx2 == -1: return file_contents, False

    start1 = file_contents.find(fixed_bytes, idx1)
    start2 = file_contents.find(fixed_bytes, idx2)
    if start1 == -1 or start2 == -1:
        print(f"未找到固定特征码 {fixed_hex}")
        return file_contents, False

    # 替换逻辑
    new_contents = bytearray(file_contents)
    # 交换 start前8个字节
    chunk1 = file_contents[start1 - 8: start1]
    chunk2 = file_contents[start2 - 8: start2]
    new_contents[start1 - 8: start1] = chunk2
    new_contents[start2 - 8: start2] = chunk1

    return new_contents, True


def modify_texture_bidirectional(folder_path, config_path, is_gun=False, current_content=None):
    if current_content is None:
        with open(os.path.join(folder_path, "BattleItem.uexp"), 'rb') as f:
            current_content = bytearray(f.read())

    suffix_hex = extract_feature_code(current_content, "A4AFC301")
    if not suffix_hex: return current_content, False
    print(f"特征码: {suffix_hex}")

    fixed_hex = calculate_fixed_hex_from_suffix(suffix_hex, is_gun)
    print(f"固定码: {fixed_hex}")

    array = parse_config_file(config_path)
    if not array: return current_content, False

    not_found = []
    for pair in array:
        A = DEC_to_HEX(pair[0])
        B = DEC_to_HEX(pair[1])
        current_content, modified = modify_file_hex(current_content, A, B, fixed_hex, suffix_hex)
        if not modified:
            not_found.append((A, B, pair[0], pair[1]))

    if not_found:
        print("\n启用备用方案...")
        new_suffix = calculate_new_suffix(fixed_hex, is_gun)
        for A, B, v1, v2 in not_found:
            current_content, modified = modify_file_hex(current_content, A, B, fixed_hex, new_suffix)
            if not modified: print(f"警告: {v1} -> {v2} 失败")

    return current_content, True


# ***************** 功能3: 普通美化 *****************
def modify_normal_beautify(folder_path, config_path, current_content=None):
    if current_content is None:
        with open(os.path.join(folder_path, "BattleItem.uexp"), 'rb') as f:
            current_content = bytearray(f.read())

    suffix = extract_feature_code(current_content, "A4AFC301")
    if not suffix: return current_content, False

    array = parse_config_file(config_path)
    if not array: return current_content, False

    pending_force = []
    for pair in array:
        A = DEC_to_HEX(pair[0], suffix)
        B = DEC_to_HEX(pair[1], suffix)
        seq1, seq2 = bytes.fromhex(A), bytes.fromhex(B)

        idx1 = current_content.find(seq1)
        idx2 = current_content.find(seq2)

        if idx1 == -1:
            print(f"未找到: {pair[0]} 跳过")
            continue
        if idx2 == -1:
            print(f"未找到: {pair[1]} 记录待处理")
            pending_force.append((A, B, pair[0], pair[1]))
            continue

        # 交换
        current_content[idx1:idx1 + len(seq1)] = seq2
        current_content[idx2:idx2 + len(seq2)] = seq1
        print(f"已交换 {pair[0]} <-> {pair[1]}")

    if pending_force:
        if input(f"是否强制更改{len(pending_force)}个单向数据？(y/n): ").strip().lower() == 'y':
            for A, B, v1, v2 in pending_force:
                seq1, seq2 = bytes.fromhex(A), bytes.fromhex(B)
                idx1 = current_content.find(seq1)
                if idx1 != -1:
                    current_content[idx1:idx1 + len(seq1)] = seq2
                    print(f"强制替换 {v1} -> {v2}")

    return current_content, True


# ***************** 功能4: 局内伪实体 *****************
def modify_data(data, A, B, hex_to_find, code3, code4):
    """复杂的数据块交换逻辑"""
    seq1, seq2 = bytes.fromhex(A), bytes.fromhex(B)
    find_bytes = bytes.fromhex(hex_to_find)
    c3_bytes, c4_bytes = bytes.fromhex(code3), bytes.fromhex(code4)

    idx1 = data.find(seq1)
    idx2 = data.find(seq2)
    if idx1 == -1 or idx2 == -1:
        print("未找到搜索序列")
        return data

    end1 = data.find(find_bytes, idx1 + len(seq1))
    end2 = data.find(find_bytes, idx2 + len(seq2))
    if end1 == -1 or end2 == -1: return data

    # 步骤1：交换头部小块
    chunk1 = data[end1 - 8: end1]
    chunk2 = data[end2 - 8: end2]
    new_data = bytearray(data)
    new_data[end1 - 8: end1] = chunk2
    new_data[end2 - 8: end2] = chunk1

    # 步骤2：定位大块区域
    # rfind 在区间 [0, idx) 搜索
    r_end3 = data.rfind(c3_bytes, 0, idx1)
    r_end4 = data.rfind(c3_bytes, 0, idx2)
    r_end5 = data.rfind(c4_bytes, 0, idx1)
    r_end6 = data.rfind(c4_bytes, 0, idx2)

    if -1 in (r_end3, r_end4, r_end5, r_end6): return data

    # 确定两个块的范围 [start, end]
    # 块1: [r_end5, r_end3], 块2: [r_end6, r_end4]
    range1 = (r_end5, r_end3)
    range2 = (r_end6, r_end4)

    # 确保 range1 在 range2 之前，方便拼接
    if range1[0] > range2[0]:
        range1, range2 = range2, range1

    s1, e1 = range1
    s2, e2 = range2

    # 提取并交换大块
    chunk_a = new_data[s1:e1]
    chunk_b = new_data[s2:e2]

    final_data = (
            new_data[:s1] +
            chunk_b +
            new_data[e1:s2] +
            chunk_a +
            new_data[e2:]
    )
    print("实体数据已修改")
    return final_data


def modify_in_game_entity(folder_path, config_path, current_content=None):
    if current_content is None:
        with open(os.path.join(folder_path, "BattleItem.uexp"), 'rb') as f:
            current_content = bytearray(f.read())

    feat1 = extract_feature_code(current_content, "A4AFC301")
    if not feat1: return False

    feat2 = calc(feat1, 0x11)
    feat3 = calc(feat1, 0xF)
    feat4 = calc(feat1, 0x1D)

    array = parse_config_file(config_path)
    if not array: return False

    for pair in array:
        A = DEC_to_HEX(pair[0], feat1)
        B = DEC_to_HEX(pair[1], feat1)
        current_content = modify_data(current_content, A, B, feat2, feat3, feat4)
        print("-" * 30)

    return current_content, True


# ***************** 功能5: 文字修改 *****************
def modify_in_game_text(folder_path, config_path, current_content=None):
    if current_content is None:
        with open(os.path.join(folder_path, "BattleItem.uexp"), 'rb') as f:
            current_content = bytearray(f.read())

    array = parse_config_file2(config_path)
    if not array: return current_content, False

    for pair in array:
        name_a, name_b = pair[0], pair[1]
        A_base = text_to_custom_format(name_a)
        B_base = text_to_custom_format(name_b)

        # 特殊硬编码补丁
        if name_a in ["特训学院上衣", "枪械挂件——P90-能量风暴"]:
            A_base += "20002000"

        # 长度对齐逻辑
        len_a, len_b = len(A_base), len(B_base)
        print(f"处理: {name_a}({len_a}) -> {name_b}({len_b})")

        if len_a == len_b:
            A, B = A_base + "0000", B_base + "0000"
        elif len_a > len_b:
            padding = "00" * ((len_a - len_b) // 2)
            A, B = A_base + "0000", B_base + padding + "0000"
        else:
            print(f"跳过: 新文本过长")
            continue

        search_b = bytes.fromhex(A)
        replace_b = bytes.fromhex(B)

        if search_b in current_content:
            current_content = current_content.replace(search_b, replace_b)
            print("文本已修改")
        else:
            print(f"未找到文本: {name_a}")

    return current_content, True


# ***************** 功能6: 特殊美化 *****************
def modify_function_six(folder_path, config_path, current_content=None):
    if current_content is None:
        with open(os.path.join(folder_path, "BattleItem.uexp"), 'rb') as f:
            current_content = bytearray(f.read())

    suffix = extract_feature_code(current_content, "50EC2101")
    if not suffix: return False

    array = parse_config_file(config_path)
    if not array: return False

    for pair in array:
        A = DEC_to_HEX(pair[0], suffix)
        B = DEC_to_HEX(pair[1], suffix)
        search_seq = bytes.fromhex(A)
        replace_seq = bytes.fromhex(B)

        count = current_content.count(search_seq)
        if count > 0:
            current_content = current_content.replace(search_seq, replace_seq)
            print(f"替换了 {count} 处: {pair[0]} -> {pair[1]}")
        else:
            print(f"未找到: {pair[0]}")

    return current_content, True


# ***********************功能7 修复透明人******************
def fix_transparent(folder_path, config_path, current_content=None):
    if current_content is None:
        with open(os.path.join(folder_path, "BattleItem.uexp"), 'rb') as f:
            current_content = bytearray(f.read())

    # 提取特征码
    search_sequence = "A4AFC301"
    suffix = extract_feature_code(current_content, search_sequence)
    if suffix is None:
        print("无法提取特征码，修改失败")
        return False

    # 解析配置
    array = parse_config_file(config_path)
    if not array:
        return False

    # 修改内容
    for pair in array:
        if int(pair[1]) < 400000 or pair[1] > 500000:
            print(f"{pair[1]} 该配置不是衣服类配置，已自动跳过！")
            continue
        A = int(403918).to_bytes(4, 'little').hex().upper() + suffix
        # print(A, DEC_to_HEX("403918"))
        B = DEC_to_HEX(pair[0], suffix)
        search_seq1 = bytes.fromhex(A)
        search_seq2 = bytes.fromhex(B)

        # index1 = merged_content.find(search_seq1)
        index2 = current_content.find(search_seq2)

        if index2 == -1:
            print(f"未找到序列：{pair[0]}")
            continue

        # 交换序列
        # merged_content[index1:index1 + len(search_seq1)] = search_seq2
        current_content[index2:index2 + len(search_seq2)] = search_seq1
        print(f"成功修复{pair[1]}")

    return current_content, True


# ==================== 主程序 ====================

def C_STedit_new():
    print("===== 时雨自动修改工具 =====")

    subfolders = get_subfolders(BASE_PATH)
    if not subfolders:
        print(f"错误：{BASE_PATH} 无子文件夹")
        return

    print("\n请选择制作区下的文件夹：")
    for i, folder in enumerate(subfolders, 1):
        print(f"{i}. {folder}")

    try:
        choice = int(input("输入序号: ")) - 1
        pakname = subfolders[choice]
        selected_folder = os.path.join(BASE_PATH, pakname)
    except (ValueError, IndexError):
        print("无效选择")
        return

    res_rel_path = find_battle_item(selected_folder)
    if not res_rel_path:
        print("错误：未找到 BattleItem.uexp")
        return

    # 准备工作目录和文件
    src_file = os.path.join(selected_folder, res_rel_path)
    work_file = os.path.join(BASE_PATH2, pakname, res_rel_path)
    battle_folder = os.path.dirname(work_file)

    copy_file_auto_create(src_file, work_file)

    modified_content = None
    is_modified = False

    while True:
        print("\n请选择修改方式：")
        options = [
            "1. 局内贴图双向", "2. 枪械贴图双向", "3. 普通美化",
            "4. 局内伪实体", "5. 局内文字修改", "6. 大厅完美枪", "7. 修复透明人"
        ]
        print("\n".join(options))

        try:
            mode = int(input("输入序号: "))
            if mode not in range(1, 8): raise ValueError
        except ValueError:
            print("无效输入")
            break

        cfg_path = input("请输入配置文件路径: ").strip().strip('"')  # 去除可能存在的引号
        if not os.path.exists(cfg_path):
            print("配置文件不存在")
            continue

        # 懒加载文件内容
        if modified_content is None:
            with open(work_file, 'rb') as f:
                modified_content = bytearray(f.read())

        success = False
        if mode == 1:
            modified_content, success = modify_texture_bidirectional(battle_folder, cfg_path, False, modified_content)
        elif mode == 2:
            modified_content, success = modify_texture_bidirectional(battle_folder, cfg_path, True, modified_content)
        elif mode == 3:
            modified_content, success = modify_normal_beautify(battle_folder, cfg_path, modified_content)
        elif mode == 4:
            modified_content, success = modify_in_game_entity(battle_folder, cfg_path, modified_content)
        elif mode == 5:
            modified_content, success = modify_in_game_text(battle_folder, cfg_path, modified_content)
        elif mode == 6:
            modified_content, success = modify_function_six(battle_folder, cfg_path, modified_content)
        elif mode == 7:
            modified_content, success = fix_transparent(battle_folder, cfg_path, modified_content)
        if success:
            is_modified = True
            print("修改已应用到内存")

        if input("\n是否继续修改？(y/n): ").strip().lower() != 'y':
            break

    # 统一保存
    if is_modified and modified_content:
        pack_dest = os.path.join(PACK_PATH, pakname, res_rel_path)
        work_dest = work_file  # 制作区路径

        for dest in [pack_dest, work_dest]:
            if write_to_destination(modified_content, dest):
                print(f"已保存: {dest}")


###################################################D_WSTedit_new########################################################
###################################################D_WSTedit_new########################################################
###################################################D_WSTedit_new########################################################
###################################################D_WSTedit_new########################################################
###################################################D_WSTedit_new########################################################
import os
import re
import shutil

# ==================== 基础路径定义 ====================
BASE_PATH = "./时雨自动/解包/"
BASE_PATH2 = "./时雨自动/制作区/"
PACK_PATH = "./时雨自动/打包/"


# ==================== 辅助函数 ====================

def get_subfolders(path):
    """获取指定路径下的子文件夹列表"""
    if not os.path.exists(path): return []
    return [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]


def write_to_destination(content, destination_file):
    """写入到目标文件，自动创建父目录"""
    try:
        os.makedirs(os.path.dirname(destination_file), exist_ok=True)
        with open(destination_file, 'wb') as dst:
            dst.write(content)
        return True
    except Exception as e:
        print(f"写入文件失败: {e}")
        return False


def copy_file_auto_create(source, dest):
    """复制文件，自动创建目录"""
    if os.path.exists(dest): return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    return shutil.copy2(source, dest)


def find_battle_item(directory, filename="Item.uasset"):
    """递归查找文件"""
    for root, _, files in os.walk(directory):
        if filename in files:
            return os.path.relpath(os.path.join(root, filename), directory)
    return None


def number_to_ascii_bytes(number):
    """数字转ASCII字节"""
    return str(number).encode('ascii')


# ==================== 配置解析 ====================

def parse_array_file_v1(array_file_path):
    """解析配置文件"""
    array = []
    invalid_lines = []

    # 辅助函数：处理数值修剪逻辑
    def clean_value(val_str):
        if val_str.endswith('00') and len(val_str) > 6:
            trimmed = val_str[:-2]
            print(f"已自动修剪：{val_str} => {trimmed}")
            return int(trimmed)
        return int(val_str)

    try:
        with open(array_file_path, 'r', encoding='utf-8-sig') as file:
            for line_num, raw_line in enumerate(file, 1):
                # 去除注释和空白
                line = re.sub(r'#.*', '', raw_line).strip()
                if not line: continue

                # 1. 处理范围格式 (例如: 100-200)
                if '-' in line:
                    match = re.match(r'^\s*(\d+)\s*-\s*(\d+)\s*$', line)
                    if match:
                        start, end = map(int, match.groups())
                        array.extend([[i, i] for i in range(start, end + 1)])
                        continue
                    else:
                        invalid_lines.append(f"行{line_num}: 范围格式错误 '{raw_line.strip()}'")
                        continue

                # 2. 处理常规对 (例如: 1001 1002)
                # 去除括号
                line = re.sub(r'[()\[\]]', '', line).strip()
                if not line:
                    invalid_lines.append(f"行{line_num}: 无效内容")
                    continue

                parts = [p for p in re.split(r'[, :=\s%-]+', line) if p]

                if len(parts) == 2 and all(p.isdigit() for p in parts):
                    val1 = clean_value(parts[0])
                    val2 = clean_value(parts[1])
                    array.append([val1, val2])
                else:
                    invalid_lines.append(f"行{line_num}: 格式无效 '{raw_line.strip()}'")

        if invalid_lines:
            print("\n发现无效配置行：")
            for msg in invalid_lines: print(f"- {msg}")

        if not array: raise ValueError("文件内容为空或无有效数据")
        return array

    except Exception as e:
        print(f"解析出错: {e}")
        return None


# ==================== 核心修改逻辑 ====================

def modify_file_hex_v1(file_contents, A, B):
    """二进制交换逻辑"""
    src = bytearray(file_contents)
    idx_a, idx_b = src.find(A), src.find(B)

    # 1. 校验有效性
    if idx_a == -1 or idx_b == -1 or idx_a == idx_b:
        print("未找到指定序列或位置相同。")
        return src, False

    # 2. 确定物理顺序 (first...second)
    # len_1/len_2 对应物理位置靠前/靠后的那个字符串的长度
    if idx_a < idx_b:
        idx_1, len_1, idx_2, len_2 = idx_a, len(A), idx_b, len(B)
        # 交换逻辑：前面的坑填 B 的内容(实际上是填 物理靠后的那个块的内容 此时需要注意逻辑)
        # 原逻辑意图：把 A 所在位置的内容换成 B 所在位置的内容。
        # 此处代码是为了提取 "数据块"。
    else:
        idx_1, len_1, idx_2, len_2 = idx_b, len(B), idx_a, len(A)

    # 3. 计算含 padding 的范围
    PAD = 3
    s1 = max(0, idx_1 - PAD)
    e1 = min(len(src), idx_1 + len_1 + PAD)

    s2 = max(0, idx_2 - PAD)
    e2 = min(len(src), idx_2 + len_2 + PAD)

    # 4. 校验重叠
    if e1 > s2:
        print("错误：数据块重叠，无法交换。")
        return src, False

    # 5. 提取并交换
    chunk_front = src[s1:e1]  # 物理靠前的数据块
    chunk_back = src[s2:e2]  # 物理靠后的数据块

    # 拼接：头部 + [后块] + 中间 + [前块] + 尾部
    # 注意：如果 idx_a < idx_b，chunk_front 是 A 的块，chunk_back 是 B 的块
    # 交换后，A 的位置变成了 B 的块，B 的位置变成了 A 的块
    new_data = src[:s1] + chunk_back + src[e1:s2] + chunk_front + src[e2:]

    print(f"交换: {A} <-> {B}")
    return new_data, True


def modify_mode_1(folder_path, config_path, current_content=None):
    if current_content is None:
        with open(os.path.join(folder_path, "Item.uasset"), 'rb') as f:
            current_content = bytearray(f.read())

    array = parse_array_file_v1(config_path)
    if not array: return False

    not_found = []
    for pair in array:
        A = number_to_ascii_bytes(pair[0])
        B = number_to_ascii_bytes(pair[1])

        # 构造搜索字节: \x00 + ASCII + \x00
        target_a = b'\x00' + A + b'\x00'
        target_b = b'\x00' + B + b'\x00'

        current_content, modified = modify_file_hex_v1(current_content, target_a, target_b)
        if not modified:
            print(f"失败: {pair[0]} <-> {pair[1]}")
            not_found.append((pair[0], pair[1]))

    return current_content, True


# ==================== 主程序 ====================

def D_WSTedit_new():
    print("===== 时雨自动修改工具 =====")

    subfolders = get_subfolders(BASE_PATH)
    if not subfolders:
        print(f"错误：{BASE_PATH} 无子文件夹")
        return

    print("\n请选择制作区下的文件夹：")
    for i, folder in enumerate(subfolders, 1):
        print(f"{i}. {folder}")

    try:
        idx = int(input("输入序号: ")) - 1
        pakname = subfolders[idx]
        selected_src_folder = os.path.join(BASE_PATH, pakname)
    except (ValueError, IndexError):
        print("无效选择")
        return

    # 查找资源文件
    res_rel_path = find_battle_item(selected_src_folder)
    if not res_rel_path:
        print("错误：未找到 Item.uasset")
        return

    # 路径准备
    src_file = os.path.join(selected_src_folder, res_rel_path)
    work_file = os.path.join(BASE_PATH2, pakname, res_rel_path)
    work_folder = os.path.dirname(work_file)  # battleitem_folder

    copy_file_auto_create(src_file, work_file)

    modified_content = None
    is_modified = False

    while True:
        print("\n请选择修改方式：\n1. 伪实体\n2. 改品质\n3. 水印")

        try:
            choice = int(input("输入序号: "))
            if choice not in [1, 2, 3]: raise ValueError
        except ValueError:
            print("无效输入")
            break

        if choice in [2, 3]:
            print("新版本伪实体包被删除暂时无法修改！")
            continue

        cfg_path = input("请输入配置文件路径: ").strip().strip('"')
        if not os.path.exists(cfg_path):
            print("配置文件不存在")
            continue

        # 懒加载文件
        if modified_content is None:
            with open(work_file, 'rb') as f:
                modified_content = bytearray(f.read())

        success = False
        if choice == 1:
            modified_content, success = modify_mode_1(work_folder, cfg_path, current_content=modified_content)

        if success:
            is_modified = True
            print("修改已应用到内存中")

        if input("\n是否继续修改？(y/n): ").strip().lower() != 'y':
            break

    # 统一保存
    if is_modified and modified_content:
        pack_dest = os.path.join(PACK_PATH, pakname, res_rel_path)
        work_dest = work_file

        for dest in [pack_dest, work_dest]:
            if write_to_destination(modified_content, dest):
                print(f"已保存: {dest}")


###################################################E_DTedit_new#########################################################
###################################################E_DTedit_new#########################################################
###################################################E_DTedit_new#########################################################
###################################################E_DTedit_new#########################################################
###################################################E_DTedit_new#########################################################
import os
import re
import shutil

# ==================== 基础路径定义 ====================
BASE_PATH = "./时雨自动/解包/"
BASE_PATH2 = "./时雨自动/制作区/"
PACK_PATH = "./时雨自动/打包/"


# ==================== 辅助工具函数 ====================

def copy_file_auto_create(source, dest):
    """复制文件，自动创建目录"""
    if os.path.exists(dest): return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    return shutil.copy2(source, dest)


def get_subfolders(path):
    """获取子文件夹"""
    if not os.path.exists(path): return []
    return [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]


def write_to_destination(content, destination_file):
    """写入文件"""
    try:
        os.makedirs(os.path.dirname(destination_file), exist_ok=True)
        with open(destination_file, 'wb') as dst:
            dst.write(content)
        return True
    except Exception as e:
        print(f"写入文件失败: {e}")
        return False


def find_battle_item(directory, filename="BattleItem_MODE_Escape.uexp"):
    """递归查找文件"""
    for root, _, files in os.walk(directory):
        if filename in files:
            return os.path.relpath(os.path.join(root, filename), directory)
    return None


# ==================== 二进制与计算函数 ====================

def dec_to_hex(decimal):
    """十进制转小端Hex字符串"""
    # 32位整数 = 4字节
    hex_str = int(decimal).to_bytes(4, 'little').hex().upper()
    print(f"十进制 {decimal} → 小端: {hex_str}")
    return hex_str


def calculate_suffix(fixed_hex, offset):
    """根据固定码和偏移计算后缀"""
    # 这里原来的逻辑是先把 hex string 转 bytes (Big Endian视角的字符串),
    # 然后 bytes 反转 (变Little Endian), 转int, 加offset
    # 最后转回 bytes (Little Endian), 转 hex string (Big Endian视角的字符串)

    # 简化：直接视为小端整数读取 -> 计算 -> 转回小端Bytes -> Hex
    val = int.from_bytes(bytes.fromhex(fixed_hex), 'little')
    val += offset
    return val.to_bytes(2, 'little').hex().upper()


def extract_features_from_pattern(merged_data, pattern):
    """提取所有特征码"""
    features = []
    pos = merged_data.find(pattern)
    while pos != -1:
        # 提取紧跟在 pattern 后的 2 字节
        feat = merged_data[pos + len(pattern): pos + len(pattern) + 2].hex().upper()
        print(f"位置 {pos} 提取特征码：{feat}")
        features.append(feat)
        pos = merged_data.find(pattern, pos + 1)

    if not features:
        print("未找到特征模式")
    return features


# ==================== 配置解析 ====================

def parse_config_file(config_path):
    valid_rules = {}

    try:
        with open(config_path, 'r', encoding='utf-8-sig') as f:
            current_section = None
            for line_num, raw_line in enumerate(f, 1):
                line = re.sub(r'#.*', '', raw_line).strip()
                if not line: continue

                # 解析 Section [xxx]
                if line.startswith("[") and line.endswith("]"):
                    current_section = line[1:-1].strip()
                    if current_section not in valid_rules:
                        valid_rules[current_section] = []
                    continue

                # 如果没有Section头，使用默认逻辑（兼容旧格式？）
                # 原代码逻辑：如果 line 不是数字行，则视为 section 名
                if not re.search(r'\d', line):
                    current_section = line.strip()
                    if current_section not in valid_rules:
                        valid_rules[current_section] = []
                    continue

                if not current_section:
                    print(f"行{line_num} 无有效节: {line}")
                    continue

                # 解析数值对
                nums = re.findall(r'\d+', line)
                if len(nums) == 2:
                    valid_rules[current_section].append((int(nums[0]), int(nums[1])))
                else:
                    print(f"行{line_num} 格式无效: {line}")

        if not valid_rules:
            print("配置文件无有效规则")
            return None

        print(f"\n解析到 {len(valid_rules)} 个节")
        return valid_rules

    except Exception as e:
        print(f"读取配置出错: {e}")
        return None


# ==================== 修改逻辑 ====================

def modify_hex(content, a_hex, b_hex, fixed_hex, suffix):
    """通用二进制交换"""
    seq_a = bytes.fromhex(a_hex + suffix)
    seq_b = bytes.fromhex(b_hex + suffix)
    fixed_bytes = bytes.fromhex(fixed_hex)

    pos_a = content.find(seq_a)
    pos_b = content.find(seq_b)

    if pos_a == -1 or pos_b == -1:
        print(f"跳过: 未找到 A/B ({a_hex}/{b_hex})")
        return content, False

    # 向前查找最近的固定码
    fix_pos_a = content.rfind(fixed_bytes, 0, pos_a)
    fix_pos_b = content.rfind(fixed_bytes, 0, pos_b)

    if fix_pos_a == -1 or fix_pos_b == -1:
        print(f"失败: 未找到固定特征码 {fixed_hex}")
        return content, False

    # 交换固定码前8字节的数据
    chunk_a = content[fix_pos_a - 8: fix_pos_a]
    chunk_b = content[fix_pos_b - 8: fix_pos_b]

    new_content = bytearray(content)
    new_content[fix_pos_a - 8: fix_pos_a] = chunk_b
    new_content[fix_pos_b - 8: fix_pos_b] = chunk_a

    print(f"交换成功: {fix_pos_a} <-> {fix_pos_b}")
    return new_content, True


def modify_hex_for_gun(content, a_hex, b_hex, suffix):
    """枪械替换逻辑"""
    src = bytes.fromhex(a_hex + suffix)
    dst = bytes.fromhex(b_hex + suffix)

    if src in content:
        new_content = content.replace(src, dst)
        print(f"替换成功: {a_hex} -> {b_hex}")
        return new_content, True

    print(f"未找到序列: {a_hex}")
    return content, False


# ==================== 主程序 ====================

def E_DTedit_new():
    print("===== 时雨自动处理工具 =====")

    subfolders = get_subfolders(BASE_PATH)
    if not subfolders:
        print(f"错误：{BASE_PATH} 无子文件夹")
        return

    print("\n请选择制作区下的文件夹：")
    for i, folder in enumerate(subfolders, 1):
        print(f"{i}. {folder}")

    try:
        idx = int(input("输入序号: ")) - 1
        pakname = subfolders[idx]
        selected_src_folder = os.path.join(BASE_PATH, pakname)
    except (ValueError, IndexError):
        print("无效选择")
        return

    res_rel_path = find_battle_item(selected_src_folder)
    if not res_rel_path:
        print("错误：未找到 BattleItem_MODE_Escape.uexp")
        return

    # 路径准备
    src_file = os.path.join(selected_src_folder, res_rel_path)
    work_file = os.path.join(BASE_PATH2, pakname, res_rel_path)

    copy_file_auto_create(src_file, work_file)

    cfg_path = input("请输入配置文件路径: ").strip().strip('"')
    if not os.path.exists(cfg_path):
        print("配置文件不存在")
        return

    # 加载文件
    with open(work_file, 'rb') as f:
        content = bytearray(f.read())

    config_rules = parse_config_file(cfg_path)
    if not config_rules: return

    is_modified = False

    # 处理逻辑
    for section, rules in config_rules.items():
        print(f"\n>>> 处理节：{section}")

        # 策略分发
        if "金光" in section:
            pattern = bytes.fromhex('000000000000CA05000000000000')
            offset = -0x0A
            is_gun_mode = False
        elif "枪" in section:
            pattern = bytes.fromhex('78CA8C3A')
            offset = 0x00
            is_gun_mode = True
        else:
            print(f"跳过未知节: {section}")
            continue

        fixed_codes = extract_features_from_pattern(content, pattern)
        if not fixed_codes: continue

        section_success = False

        # 尝试所有特征码
        for fixed_hex in fixed_codes:
            print(f"\n--- 尝试特征码: {fixed_hex} ---")
            temp_content = content.copy()  # 在临时副本上操作

            # 记录失败项用于二次尝试
            failed_rules = []
            current_pass_success = True

            suffix = calculate_suffix(fixed_hex, offset)

            for a_val, b_val in rules:
                a_hex = dec_to_hex(a_val)
                b_hex = dec_to_hex(b_val)

                if is_gun_mode:
                    temp_content, ok = modify_hex_for_gun(temp_content, a_hex, b_hex, suffix)
                else:
                    temp_content, ok = modify_hex(temp_content, a_hex, b_hex, fixed_hex, suffix)

                if not ok:
                    failed_rules.append((a_val, b_val))
                    current_pass_success = False

            # 金光模式的二次尝试逻辑 (offset + 11)
            if not is_gun_mode and failed_rules:
                print("\n启用备用后缀尝试...")
                alt_suffix = calculate_suffix(fixed_hex, offset + 11)
                for a_val, b_val in failed_rules:
                    a_hex = dec_to_hex(a_val)
                    b_hex = dec_to_hex(b_val)
                    temp_content, ok = modify_hex(temp_content, a_hex, b_hex, fixed_hex, alt_suffix)
                    if ok:
                        print(f"备用方案成功: {a_val} <-> {b_val}")
                        # 从失败列表中移除（虽然这里不影响逻辑了，但在复杂场景下有用）
                        # failed_rules.remove((a_val, b_val)) 
                    else:
                        current_pass_success = False

            # 如果这一轮尝试有效（哪怕只有部分），应用更改
            # 这里策略改为：只要有变动就应用
            if temp_content != content:
                content = temp_content
                is_modified = True
                section_success = True
                print(f"特征码 {fixed_hex} 应用完成")
                break  # 只要一个特征码成功应用了规则，通常就跳出特征码循环处理下一节

        if not section_success:
            print(f"节 {section} 所有尝试均无变化")

    # 保存
    if is_modified:
        pack_dest = os.path.join(PACK_PATH, pakname, res_rel_path)
        work_dest = work_file

        for dest in [pack_dest, work_dest]:
            if write_to_destination(content, dest):
                print(f"已保存: {dest}")


###################################################F_CodeExtract_new####################################################
###################################################F_CodeExtract_new####################################################
###################################################F_CodeExtract_new####################################################
###################################################F_CodeExtract_new####################################################
###################################################F_CodeExtract_new####################################################
import re
import os
from datetime import datetime


# ==================== 基础工具函数 ====================
def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.readlines()


def write_file(file_path, lines):
    with open(file_path, 'w', encoding='utf-8') as file:
        file.writelines(lines)


# ==================== 功能1：添加注释 ====================
def add_comments():
    input_file_path = input("要加注释的py或者txt路径：").strip('"')
    search_file_path = input("和平代码路径：").strip('"')

    if not os.path.exists(input_file_path) or not os.path.exists(search_file_path):
        print("文件路径不存在，请检查")
        return

    lines = read_file(input_file_path)

    # 建立两个映射表
    map_col2 = {}  # 第二列 -> 中文 (优先)
    map_col1 = {}  # 第一列 -> 中文 (备用)

    with open(search_file_path, 'r', encoding='utf-8') as file:
        for line in file:
            parts = line.split(' -- ')
            if len(parts) > 2:
                col1 = parts[0].strip()
                col2 = parts[1].strip()
                chinese = parts[2].strip()

                # 分别存入两个字典
                map_col2[col2] = chinese
                map_col1[col1] = chinese

    modified_lines = []
    for line in lines:
        numbers = re.findall(r'\d+', line)
        comments = []

        for num in numbers:
            # 逻辑：先找第二列，找不到再找第一列
            if num in map_col2:
                comments.append(map_col2[num])
            elif num in map_col1:
                comments.append(map_col1[num])

        if comments:
            additional_text = '改'.join(comments)
            # 防止重复添加注释
            if ' # ' in line:
                modified_lines.append(line)
            else:
                new_line = line.rstrip('\n') + ' # ' + additional_text + '\n'
                modified_lines.append(new_line)
        else:
            modified_lines.append(line)

    write_file(input_file_path, modified_lines)
    print(f"注释已添加至 {input_file_path}")


# ==================== 解码相关工具 ====================
def custom_format_to_text(hex_data, encode):
    hex_data = re.sub(r'[^0-9A-Fa-f]', '', hex_data).upper()

    if not hex_data or len(hex_data) < 2: return ''
    if len(hex_data) % 2 != 0: hex_data = hex_data[:-1]

    if encode == 'utf':
        result = try_utf16le_decode(hex_data)
        if result: return result

    if encode == 'ascii':
        result = try_ascii_decode(hex_data)
        if result: return result
    return None


def try_ascii_decode(hex_data):
    result = []
    valid_count = 0
    total = len(hex_data) // 2
    for i in range(0, len(hex_data), 2):
        try:
            byte_val = int(hex_data[i:i + 2], 16)
            if 32 <= byte_val <= 126:
                result.append(chr(byte_val))
                valid_count += 1
            elif byte_val == 0:
                return None
            else:
                result.append(' ')
        except ValueError:
            return None
    if total > 0 and valid_count / total >= 0.8:
        return ''.join(result).strip()
    return None


def try_utf16le_decode(hex_data):
    if len(hex_data) % 4 != 0: hex_data = hex_data[:-(len(hex_data) % 4)]
    if not hex_data: return None

    result = []
    valid_count = 0
    total = len(hex_data) // 4
    for i in range(0, len(hex_data), 4):
        hex_code = hex_data[i:i + 4]
        try:
            swapped = hex_code[2:4] + hex_code[0:2]
            unicode_code = int(swapped, 16)
            if (32 <= unicode_code <= 55295) or (57344 <= unicode_code <= 65533):
                char = chr(unicode_code)
                if char.isprintable():
                    result.append(char)
                    valid_count += 1
                else:
                    result.append(' ')
        except (ValueError, UnicodeEncodeError):
            continue
    if total > 0 and valid_count / total >= 0.5:
        return ''.join(result).strip()
    return None


def hex_to_reversed_int(hex_str):
    if len(hex_str) != 8: return 0
    try:
        reversed_hex = ''.join([hex_str[i - 2:i] for i in range(8, 0, -2)])
        return int(reversed_hex, 16)
    except ValueError:
        return 0


def get_feature_code(input_file, dt):
    try:
        with open(input_file, 'rb') as f:
            # 读取整个文件可能会很大，但为了获取特征码，可以只读取开头的一部分
            # 不过原逻辑是 read().hex()，这里为了稳妥读取前 50MB
            # 如果特征码可能在文件尾部，建议还是读取全部
            hex_data = f.read().hex().upper()
            target = 'C4B58C3A' if dt else '78274930'
            index = hex_data.find(target)
            if index == -1: return None
            end_index = index + 8 + 4
            if end_index > len(hex_data): return None
            return hex_data[index + 8:end_index]
    except Exception:
        return None


# ==================== 核心处理 (含距离判断) ====================
# ==================== 核心处理 (优化版) ====================

def process_file(input_file, first_hex, second_hex, third_hex, forth_hex=None):
    first_hex = first_hex.upper()
    second_hex = second_hex.upper()
    third_hex = third_hex.upper()

    # 预编译正则，提升速度
    regex_first = re.compile(first_hex)
    regex_second = re.compile(second_hex)
    regex_third = re.compile(third_hex)
    regex_ffff = re.compile(r'[0-9A-F][0-9A-F]FFFFFF')
    regex_ffff2 = re.compile(r'[0-9A-F][0-9A-F]000000')

    # 搜索窗口大小 (Hex字符数)。
    # 既然你后面的逻辑限制了 third - first < 480，那我们往后搜 2000 字符绰绰有余
    # 这样避免了每次都搜索整个剩余文件，极大提升速度
    SEARCH_WINDOW_SIZE = 64 * 1024 * 2

    try:
        with open(input_file, 'rb') as f:
            # 读取整个文件
            hex_data = f.read().hex().upper()
            results = []

            # 查找所有匹配 first_hex 的位置
            # finditer 返回的是迭代器，内存占用低
            for match in regex_first.finditer(hex_data):
                first_pos = match.start()

                if first_pos < 8: continue

                # 1. 提取第一个数值
                preceding_hex = hex_data[first_pos - 8:first_pos]
                reversed_int1 = hex_to_reversed_int(preceding_hex)
                if reversed_int1 == 0:
                    continue
                # === 优化核心 ===
                # 不再切片到文件末尾，只切片一小块窗口
                window_end = min(first_pos + SEARCH_WINDOW_SIZE, len(hex_data))
                search_window = hex_data[first_pos:window_end]

                # 2. 在窗口内搜索 second_hex
                second_match = regex_second.search(search_window)

                if not second_match: continue

                # 注意：这里的 start() 是相对于 search_window 的偏移量
                second_relative_pos = second_match.start()
                second_start_pos = first_pos + second_relative_pos

                # 定义 FFFF 搜索范围
                range_hex = search_window[:second_relative_pos]

                # 3. 搜索 FFFF
                matches = list(regex_ffff.finditer(range_hex))
                if matches:
                    ffff_relative_pos = matches[-1].start()
                    ffff_pos = first_pos + ffff_relative_pos
                    if ffff_pos % 2 != 0: ffff_pos += 1
                else:
                    ffff_pos = -1

                t = False
                if ffff_pos < first_pos + 8:
                    matches = list(regex_ffff2.finditer(range_hex))
                    if matches:
                        ffff_relative_pos = matches[-1].start()
                        ffff_pos = first_pos + ffff_relative_pos
                        if ffff_pos % 2 != 0: ffff_pos += 1
                    else:
                        ffff_pos = -1
                    t = True
                    if ffff_pos < first_pos + 8: continue

                # 提取字符串 Hex
                extracted_hex = hex_data[ffff_pos + 8: second_start_pos - (2 if t else 4)]
                if len(extracted_hex) < 4: continue

                # 解码字符串
                converted_text = custom_format_to_text(extracted_hex, 'ascii' if t else 'utf')
                if not converted_text: continue

                # 4. 搜索 third_hex
                # 我们依然只在那个小窗口剩下的部分里搜，不要搜整个文件
                search_window_rest = search_window[second_relative_pos:]
                third_match = regex_third.search(search_window_rest)

                if not third_match: continue

                third_relative_pos = second_relative_pos + third_match.start()
                third_start_pos = first_pos + third_relative_pos

                # 距离判断: 240字节 = 480 Hex
                if (third_start_pos - first_pos) > 480:
                    continue

                if third_start_pos < second_start_pos + 8: continue

                # 提取第二个数值
                preceding_hex2 = hex_data[third_start_pos - 8:third_start_pos]
                reversed_int2 = hex_to_reversed_int(preceding_hex2)

                results.append(f'{reversed_int1} -- {reversed_int2} -- {converted_text}')

            return results

    except Exception as e:
        print(f"处理文件出错: {e}")
        import traceback
        traceback.print_exc()
        return []


def execute_extraction(input_file, mode_choice):
    if not os.path.exists(input_file):
        print(f'文件不存在: {input_file}')
        return []
    is_subway = (mode_choice == "2")
    third_seq = get_feature_code(input_file, is_subway)
    if not third_seq or not re.match(r'^[0-9A-Fa-f]{4}$', third_seq):
        print("特征码无效")
        return []

    try:
        first_byte = int(third_seq[0:2], 16) + 11
        first_seq = format(first_byte, '02X') + third_seq[2:4]
        second_byte = int(first_seq[0:2], 16) + 4
        second_seq = format(second_byte, '02X') + first_seq[2:4]
    except ValueError:
        return []

    print(f"正在分析 {input_file} ...")
    # 修改：直接处理整个文件，不再分片
    all_results = process_file(input_file, first_seq, second_seq, third_seq)

    return list(dict.fromkeys(all_results))


# ==================== 伪实体提取逻辑 (ASCII 1000 + 00 + 8字节间隔) ====================

def get_pseudo_entity_list(input_file):
    if not os.path.exists(input_file):
        print(f'文件不存在: {input_file}')
        return []

    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"读取文件出错: {e}")
        return []

    start_pattern = b'1000'
    cursor = data.find(start_pattern)

    if cursor == -1:
        print("未找到起始标识 1000")
        return []

    results = []
    file_len = len(data)
    GAP_SIZE = 8

    print("正在提取伪实体数据...")
    while cursor < file_len:
        null_pos = data.find(b'\x00', cursor)
        if null_pos == -1: break

        chunk = data[cursor:null_pos]
        try:
            text = chunk.decode('ascii')
            if text:
                results.append(text)
            else:
                break
        except UnicodeDecodeError:
            break

        next_cursor = null_pos + 1 + GAP_SIZE
        if next_cursor >= file_len: break
        cursor = next_cursor

    print(f"提取完成，共 {len(results)} 条数据。")
    return results


# ==================== 功能2：自动输出代码 ====================

def process_single_file_for_output(input_file, output_file, third_seq):
    # 此函数逻辑已重构，直接处理单个文件
    third_seq = third_seq.upper()
    if len(third_seq) != 4:
        print('特征码格式无效')
        return
    try:
        first_byte = int(third_seq[0:2], 16) + 11
        first_byte_hex = format(first_byte, '02X')
        second_byte = third_seq[2:4]
        first_seq = first_byte_hex + second_byte

        first_byte = int(first_seq[0:2], 16) + 4
        first_byte_hex = format(first_byte, '02X')
        second_byte = first_seq[2:4]
        second_seq = first_byte_hex + second_byte

        first_byte = int(first_seq[0:2], 16) + 18
        first_byte_hex = format(first_byte, '02X')
        forth_byte = first_seq[2:4]
        forth_seq = first_byte_hex + forth_byte
    except ValueError:
        print('特征码转换失败')
        return

    print(f'正在分析文件: {input_file}')
    # 调用核心处理函数
    results = process_file(input_file, first_seq, second_seq, third_seq, forth_seq)

    if results:
        unique_results = list(dict.fromkeys(results))
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_results))
        print(f'输出完成，已保存到：{output_file}')
        print("如果出现乱码，肯定是因为有英文导致的，把custom_format_to_text改一下就行了")
    else:
        print('未找到有效结果，未生成输出文件')


def auto_output_code():
    continue_choice = input("请选择需要输出的模式: \n1.输出实体代码\n2.输出地铁代码\n选择模式：").strip()
    if continue_choice == "1":
        input_file = input(r'请输入\Content\CSV\BattleItem.uexp文件路径: ').strip('"')
        if not os.path.exists(input_file):
            print('输入文件不存在，请检查路径')
            return
    elif continue_choice == "2":
        input_file = input(r'请输入\Content\CSV\BattleItem_MODE_Escape.uexp文件路径: ').strip('"')
        if not os.path.exists(input_file):
            print('输入文件不存在，请检查路径')
            return
    else:
        print("无效的选择")
        return

    if continue_choice == "1":
        third_seq = get_feature_code(input_file, False)
    else:
        third_seq = get_feature_code(input_file, True)

    print(f'特征码：{third_seq}')
    if not third_seq or not re.match(r'^[0-9A-Fa-f]{4}$', third_seq):
        print("特征码提取失败")
        return
    print(f'自动提取到特征码：{third_seq}')

    current_time = datetime.now().strftime('%m月%d日%H时%M分%S')
    if continue_choice == "1":
        output_file_name = f'{current_time}时雨和平经典全局输出.h'
    else:
        output_file_name = f'{current_time}时雨和平地铁全局输出.h'
    output_file_path = os.path.join(os.path.join(os.path.expanduser("~"), "Desktop"), output_file_name)

    # 修改：直接调用单文件处理函数
    process_single_file_for_output(input_file, output_file_path, third_seq)


# ==================== 功能3：偷配置对比 (含去重逻辑) ====================
def steal_config_compare():
    print("\n=== 偷配置对比 ===")
    mode_choice = input("模式:\n1.实体\n2.地铁\n3.伪实体\n选择操作: ").strip()
    if mode_choice not in ["1", "2", "3"]: return
    if mode_choice == "1":
        f1 = input(r"【原版\Content\CSV\BattleItem.uexp】路径: ").strip('"')
        f2 = input(r"【改版\Content\CSV\BattleItem.uexp】路径: ").strip('"')
    if mode_choice == "2":
        f1 = input(r"【原版\Content\CSV\BattleItem_MODE_Escape.uexp】路径: ").strip('"')
        f2 = input(r"【改版\Content\CSV\BattleItem_MODE_Escape.uexp】路径: ").strip('"')
    if mode_choice == "3":
        f1 = input(r"【原版\Content\CSV\Item.uasset】路径: ").strip('"')
        f2 = input(r"【改版\Content\CSV\Item.uasset】路径: ").strip('"')
    # 准备对比列表 my_list (用于记录文件1中出现过的代码)
    my_list = []
    differences = []

    # === 伪实体模式 ===
    if mode_choice == "3":
        print("\n提取旧文件 (伪实体)...")
        list1 = get_pseudo_entity_list(f1)
        print("\n提取新文件 (伪实体)...")
        list2 = get_pseudo_entity_list(f2)

        if not list1 or not list2:
            print("提取失败")
            return

        print("开始对比 (伪实体模式)...")
        # 伪实体没有IDKey，依然只能按顺序 zip 对比，但可以加入 my_list 过滤值
        for idx, (old_val, new_val) in enumerate(zip(list1, list2)):

            # === 用户指定的过滤逻辑 ===
            if new_val in my_list:
                continue
            else:
                my_list.append(old_val)
            # ========================

            if old_val != new_val:
                differences.append(f"[{old_val},{new_val}]")

    # === 实体/地铁模式 ===
    else:
        print("\n提取旧文件...")
        # execute_extraction 已经修改为直接处理文件，无需担心分片
        list1 = execute_extraction(f1, mode_choice)
        print("\n提取新文件...")
        list2 = execute_extraction(f2, mode_choice)

        if not list1 or not list2:
            print("提取失败")
            return

        print("\n正在处理名称映射...")
        global_name_map = {}

        def fill_names(data_list):
            for line in data_list:
                parts = line.strip().split(' -- ')
                if len(parts) > 2:
                    global_name_map[parts[0]] = parts[2]
                    global_name_map[parts[1]] = parts[2]

        fill_names(list1)
        # 建立旧文件索引 {ID: Value}
        old_value_map = {}
        for line in list1:
            parts = line.strip().split(' -- ')
            if len(parts) >= 2:
                old_value_map[parts[0]] = parts[1]

        print("开始对比 (实体/地铁模式)...")
        for line in list2:
            parts = line.strip().split(' -- ')
            if len(parts) >= 2:
                key_id = parts[0]
                new_val = parts[1]  # code2 (新)

                if key_id in old_value_map:
                    old_val = old_value_map[key_id]  # code1 (旧)

                    # === 用户指定的过滤逻辑 ===
                    tmp = global_name_map.get(new_val, "未知")
                    if tmp == "未知":
                        name_a = global_name_map.get(old_val, "未知")
                        name_b = global_name_map.get(new_val, "未知")
                        differences.append(f"[{old_val},{new_val}] # {name_a} 改 {name_b}")
                        continue

                    if new_val in my_list:
                        continue
                    else:
                        my_list.append(key_id)
                        my_list.append(old_val)
                    # ========================

                    if old_val != new_val:
                        name_a = global_name_map.get(old_val, "未知")
                        name_b = global_name_map.get(new_val, "未知")
                        differences.append(f"[{old_val},{new_val}] # {name_a} 改 {name_b}")

    # === 输出结果 ===
    if differences:
        if mode_choice == "1":
            out_name = f'经典偷配置{datetime.now().strftime("%H%M%S")}.txt'
        if mode_choice == "2":
            out_name = f'地铁偷配置{datetime.now().strftime("%H%M%S")}.txt'
        if mode_choice == "3":
            out_name = f'伪实体偷配置{datetime.now().strftime("%H%M%S")}.txt'

        out_path = os.path.join(os.path.expanduser("~"), "Desktop", out_name)
        with open(out_path, 'w', encoding='utf-8') as f:
            # f.write(f"// 模式: {mode_choice} | 差异总数: {len(differences)}\n\n")
            f.write('\n'.join(differences))
        print(f"\n对比完成！发现 {len(differences)} 处差异。")
        print(f"结果在桌面: {out_name}")
    else:
        print("\n数据完全一致 (未发现修改或已被过滤)。")


# ==================== 主程序 ====================
def F_CodeExtract_new():
    while True:
        print("\n1. 加注释")
        print("2. 自动输出代码")
        print("3. 偷配置对比")
        print("0. 退出")

        c = input("选择操作: ").strip()
        if c == "0":
            break
        elif c == "1":
            add_comments()
        elif c == "2":
            auto_output_code()
        elif c == "3":
            steal_config_compare()


###################################################H_WideAngle_new######################################################
###################################################H_WideAngle_new######################################################
###################################################H_WideAngle_new######################################################
###################################################H_WideAngle_new######################################################
###################################################H_WideAngle_new######################################################
import os
import shutil
import struct

# 预定义基础路径
UNPACK_DIR = "时雨自动/解包/"
WORK_DIR = "时雨自动/制作区/"
PACK_DIR = "时雨自动/打包/"


def get_subfolders(path):
    """获取子文件夹"""
    if not os.path.exists(path): return []
    return [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]


def float_to_bytes(value):
    """浮点转小端字节"""
    return struct.pack("<f", float(value))


def write_to_destination(content, destination_file):
    """写入文件，自动创建目录"""
    try:
        os.makedirs(os.path.dirname(destination_file), exist_ok=True)
        with open(destination_file, 'wb') as dst:
            dst.write(content)
        return True
    except Exception as e:
        print(f"写入文件失败: {e}")
        return False


def modify_mode_1(content, value, is_wide_mode, value2=None):
    """核心修改逻辑"""
    # 确保操作的是 bytearray
    if not isinstance(content, bytearray):
        content = bytearray(content)

    val_bytes = float_to_bytes(value)

    if is_wide_mode:
        # 广角修改：替换 220.0 (00 00 5C 43)
        old_bytes = bytes([0x00, 0x00, 0x5C, 0x43])
        count = content.count(old_bytes)
        print(f"找到 {count} 处广角数据")
        content = content.replace(old_bytes, val_bytes)
    else:
        # 速度修改
        # 1. 游泳速度 (00 80 BB 43) -> value2
        target_swim = bytes.fromhex("0080BB43")
        if value2 is not None:
            content = content.replace(target_swim, float_to_bytes(value2))

        # 2. 奔跑触发 (B7 FE FF FF) -> 00 00 00 00
        target_trigger = bytes.fromhex("B7FEFFFF")
        content = content.replace(target_trigger, bytes(4))  # 4个0x00

        # 3. 奔跑速度 (00 80 20 43) -> value
        target_run = bytes.fromhex("00802043")
        content = content.replace(target_run, val_bytes)

        print(f"速度参数已应用: 奔跑速度={value}, 游泳速度={value2}")

    return content, True


def find_battle_item(directory, filename="BP_PlayerPawn.uexp"):
    """递归查找文件"""
    for root, _, files in os.walk(directory):
        if filename in files:
            return os.path.relpath(os.path.join(root, filename), directory)
    return None


def get_float_input(prompt, default=None):
    """获取浮点数输入的辅助函数"""
    val = input(prompt).strip()
    if not val and default is not None:
        return default
    return float(val)


def H_WideAngle_new():
    print("===== 时雨自动修改工具 =====")

    if not os.path.exists(UNPACK_DIR):
        print(f"错误：路径 {UNPACK_DIR} 不存在")
        return

    subfolders = get_subfolders(UNPACK_DIR)
    if not subfolders:
        print(f"错误：{UNPACK_DIR} 下没有子文件夹")
        return

    print("\n请选择制作区下的文件夹：")
    for i, folder in enumerate(subfolders, 1):
        print(f"{i}. {folder}")

    try:
        idx = int(input("输入序号: ")) - 1
        if not (0 <= idx < len(subfolders)): raise ValueError
        pakname = subfolders[idx]
        selected_src_folder = os.path.join(UNPACK_DIR, pakname)
    except (ValueError, IndexError):
        print("无效选择")
        return

    print(f"\n已选择: {pakname}")

    # 查找关键文件
    res_rel_path = find_battle_item(selected_src_folder)
    if not res_rel_path:
        print("错误：未找到 BP_PlayerPawn.uexp 文件！")
        return

    # 准备工作区路径
    work_file_path = os.path.join(WORK_DIR, pakname, res_rel_path)
    src_file_path = os.path.join(selected_src_folder, res_rel_path)

    # 复制文件到制作区 (如果不存在)
    if not os.path.exists(work_file_path):
        os.makedirs(os.path.dirname(work_file_path), exist_ok=True)
        shutil.copy2(src_file_path, work_file_path)

    print("\n请选择修改方式：\n1. 超广角修改\n2. 加速修改")
    try:
        modify_choice = int(input("输入序号: "))
        if modify_choice not in [1, 2]: raise ValueError
    except ValueError:
        print("无效输入")
        return

    # 获取输入参数
    try:
        val1, val2 = 0.0, 0.0
        if modify_choice == 1:
            val1 = get_float_input("请输入广角值 (默认220): ", 220.0)
        else:
            val1 = get_float_input("请输入奔跑速度 (建议300已经很明显): ")
            val2 = get_float_input("请输入游泳速度 (默认约380): ")
    except ValueError:
        print("错误：请输入有效的数字")
        return

    if input("\n确认执行修改？(y/n): ").strip().lower() != "y":
        print("操作已取消")
        return

    print("-" * 50)

    # 读取、修改、保存
    with open(work_file_path, 'rb') as f:
        content = bytearray(f.read())

    # 调用修改逻辑
    is_wide = (modify_choice == 1)
    new_content, success = modify_mode_1(content, val1, is_wide, val2)

    if success:
        print("修改已应用到内存")
        # 统一保存到 打包区 和 制作区
        save_paths = [
            os.path.join(PACK_DIR, pakname, res_rel_path),
            work_file_path  # 覆盖制作区文件
        ]

        for dest in save_paths:
            if write_to_destination(new_content, dest):
                print(f"成功保存: {dest}")


###################################################I_ClothApp_new#######################################################
###################################################I_ClothApp_new#######################################################
###################################################I_ClothApp_new#######################################################
###################################################I_ClothApp_new#######################################################
###################################################I_ClothApp_new#######################################################
import os
import re
import os.path
import shutil

BASE_PATH = "./时雨自动/解包/"
BASE_PATH2 = "./时雨自动/制作区/"
PACK_PATH = "./时雨自动/打包/"


def write_to_destination(content, destination_file):
    """写入到目标文件"""
    try:
        # 确保目录存在
        destination_dir = os.path.dirname(destination_file)
        if destination_dir:
            os.makedirs(destination_dir, exist_ok=True)

        with open(destination_file, 'wb') as dst:
            dst.write(content)
        # print(f"已成功写入文件: {destination_file}")
        return True
    except Exception as e:
        print(f"写入文件失败: {e}")
        return False


def get_subfolders(path):
    """获取指定路径下的子文件夹列表"""
    if not os.path.exists(path):
        return []
    return [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]


def find_battle_item(directory, filename):
    for root, dirs, files in os.walk(directory):
        if filename in files:
            full_path = os.path.join(root, filename)
            return os.path.relpath(full_path, directory)
    return None


def copy_file_auto_create(source, dest):
    """复制文件，自动创建目录，目标存在则跳过"""
    if os.path.exists(dest):
        return dest

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    return shutil.copy2(source, dest)


def parse_array_file_v1(array_file_path):
    array = []
    invalid_lines = []
    separators = r'[, :=\s%-]'

    try:
        with open(array_file_path, 'r', encoding='utf-8-sig') as file:
            for line_num, raw_line in enumerate(file, 1):
                original_line = raw_line.strip()
                line = re.sub(r'#.*', '', original_line).strip()
                if not line:
                    continue

                if '-' in line and re.match(r'^\s*\d+\s*-\s*\d+\s*$', line):
                    try:
                        start, end = map(int, re.split(r'\s*-\s*', line))
                        array.extend([[i, i] for i in range(start, end + 1)])
                        continue
                    except:
                        invalid_lines.append(f"行{line_num}: 范围格式错误 '{original_line}'")
                        continue

                line = re.sub(r'[()\[\]]', '', line).strip()
                if not line:
                    invalid_lines.append(f"行{line_num}: 去除括号后无有效内容 '{original_line}'")
                    continue

                parts = re.split(separators, line)
                parts = [p.strip() for p in parts if p.strip()]

                if len(parts) == 2 and all(p.isdigit() for p in parts):
                    if parts[0].endswith('00') and len(parts[0]) > 6:
                        val1 = int(parts[0][:-2])
                        print("已自动修剪：" + str(int(parts[0])) + "=>" + str(int(parts[0][:-2])))
                    else:
                        val1 = int(parts[0])
                    if parts[1].endswith('00') and len(parts[1]) > 6:
                        val2 = int(parts[1][:-2])
                        print("已自动修剪：" + str(int(parts[1])) + "=>" + str(int(parts[1][:-2])))
                    else:
                        val2 = int(parts[1])
                    array.append([val1, val2])
                else:
                    invalid_lines.append(f"行{line_num}: 格式无效 '{original_line}'")

        if invalid_lines:
            print("\n发现无效配置行：")
            for msg in invalid_lines:
                print(f"- {msg}")

        if not array:
            raise ValueError("数组文件内容为空或格式不正确")
        return array

    except FileNotFoundError:
        print(f"错误：配置文件 {array_file_path} 不存在")
        return None
    except Exception as e:
        print(f"读取或解析数组文件时出错: {e}")
        return None


def number_to_ascii_bytes(number_str):
    """
    将数字字符串转换为对应的ASCII码字节数组
    """
    return bytes(str(number_str), 'ascii')


def modify_file_hex_v1(file_contents, help_content, A, B):
    src = bytearray(file_contents)
    src1 = bytearray(help_content)
    idx_a, idx_b = src1.find(A), src.find(B)

    # 1. 找不到或位置重合（无法交换）
    if idx_a == -1:
        print("未找到指定序列A")
        return src, False
    if idx_b == -1:
        print("未找到指定序列B")
        return src, False
    # 3. 计算含 padding 的切片范围（增加 max/min 防止越界）
    pad = 4
    s1, e1 = idx_a, idx_a + len(A) + pad
    s2, e2 = idx_b, idx_b + len(B) + pad

    # 5. 定义数据块（直接从源数据提取）
    chunk_1 = src1[s1:e1]  # 物理靠前的数据块
    chunk_2 = src[s2:e2]  # 物理靠后的数据块
    # print(chunk_1, chunk_2)
    # 6. 拼接：头部 + [后块] + 中间 + [前块] + 尾部
    # 注意：这里完成了“交换”——在位置1放了chunk_2，在位置2放了chunk_1
    new_data = src.replace(chunk_2, chunk_1)
    print("成功替换：", A, B)
    return new_data, True


def modify_mode_1(folder_path, config_path, current_content=None):
    if current_content is None:
        # 读取原始文件
        battle_item_path = os.path.join(folder_path, "LobbyAvatarExtEffect.uasset")
        with open(battle_item_path, 'rb') as f:
            current_content = bytearray(f.read())
    help_item_path = os.path.join(folder_path, "BattleItem.uasset")
    with open(help_item_path, 'rb') as f1:
        help_content = bytearray(f1.read())
    # fixed_hex = extract_fixed_hex(merged_content)
    # if fixed_hex is None:
    #     return False

    # suffix_hex = calculate_suffix(fixed_hex)
    # suffix_hex = "2C 23"
    # print(f"后缀特征码为: {suffix_hex}")

    array = parse_array_file_v1(config_path)
    if not array:
        return current_content, True

    not_found_pairs = []
    for pair in array:
        if int(pair[1]) < 400000 or pair[1] > 500000:
            print(f"{pair[1]} 该配置不是衣服类配置，已自动跳过！")
            continue
        A = number_to_ascii_bytes(pair[0])
        B = number_to_ascii_bytes(pair[1])

        current_content, modified = modify_file_hex_v1(current_content, help_content, b'\x00' + A + b'\x00',
                                                       b'\x00' + B + b'\x00')
        if not modified:
            print(pair[0], pair[1])
            not_found_pairs.append((A, B))
    return current_content, True


# ***************************************************************************************************
def extract_feature_code(merged_data, search_sequence):
    """从合并后的数据中提取特征码"""
    index = merged_data.find(bytes.fromhex(search_sequence))
    if index == -1:
        print(f"未找到序列：{search_sequence}")
        return None
    if index + 6 <= len(merged_data):
        feature_code = merged_data[index + 4:index + 6].hex().upper()
        return feature_code
    else:
        print("序列后面没有足够的数据")
        return None


def DEC_to_HEX(decimal_number, suffix=""):
    """将十进制数转换为八位十六进制数（小端序）"""
    hex_number = format(int(decimal_number), '08X')
    hex_array = [hex_number[i:i + 2] for i in range(0, 8, 2)]
    reversed_hex_array = hex_array[::-1]
    reversed_hex_number = ''.join(reversed_hex_array)
    result = reversed_hex_number + suffix
    print(f"{decimal_number} 转换为：{result}")
    return result


def modify_mode_2(folder_path, config_path, current_content=None):
    if current_content is None:
        battle_item_path = os.path.join(folder_path, "DeadlistAndBox.uexp")
        with open(battle_item_path, 'rb') as f:
            current_content = bytearray(f.read())

    # 提取特征码
    search_sequence = "57C90D00"
    suffix = extract_feature_code(current_content, search_sequence)
    if suffix is None:
        print("无法提取特征码，修改失败")
        return current_content, False

    # 解析配置
    array = parse_array_file_v1(config_path)
    if not array:
        return current_content, False

    my_list = []
    # 修改内容
    for pair in array:
        if int(pair[1]) < 400000 or pair[1] > 500000:
            print(f"{pair[1]} 该配置不是衣服类配置，已自动跳过！")
            continue
        A = DEC_to_HEX(pair[0], suffix)
        B = DEC_to_HEX(pair[1], suffix)
        search_seq1 = bytes.fromhex(A)
        search_seq2 = bytes.fromhex(B)

        index1 = current_content.find(search_seq1)
        index2 = current_content.find(search_seq2)

        if index1 == -1:
            print(f"未找到序列：{pair[0]} 自动跳过")
            continue
        if index2 == -1:
            print(f"未找到序列：{pair[1]} 已自动记录")
            my_list.append([A, B])
            continue

        # 交换序列
        current_content[index1:index1 + len(search_seq1)] = search_seq2
        current_content[index2:index2 + len(search_seq2)] = search_seq1
        print(f"成功交换 {pair[0]} 和 {pair[1]}")

    if my_list:
        continue_choice = input(f"是否强制更改{len(my_list)}个数据？(y/n): ").strip().lower()
        if continue_choice == 'y':
            for pair in my_list:
                search_seq1 = bytes.fromhex(pair[0])
                search_seq2 = bytes.fromhex(pair[1])
                index1 = current_content.find(search_seq1)
                current_content[index1:index1 + len(search_seq1)] = search_seq2
                print(f"成功交换 {pair[0]} 和 {pair[1]}")
    return current_content, True


def I_ClothApp_new():
    print("===== 时雨自动修改工具 =====")

    # 1. 选择制作区下的文件夹
    subfolders = get_subfolders(BASE_PATH)
    if not subfolders:
        print(f"错误：{BASE_PATH} 下没有子文件夹")
        return

    print("\n请选择制作区下的文件夹：")
    for i, folder in enumerate(subfolders, 1):
        print(f"{i}. {folder}")

    try:
        choice = int(input("输入序号: ")) - 1
        selected_folder = os.path.join(BASE_PATH, subfolders[choice])
        pakname = subfolders[choice]
    except (ValueError, IndexError):
        print("无效选择")
        return

    while True:
        # 选择修改方式
        print("\n请选择修改方式：")
        modify_options = [
            "1. 人物动作修改",
            "2. 人物出场修改",
            "3. 淘汰播报修改",
        ]
        for opt in modify_options:
            print(opt)

        try:
            modify_choice = int(input("输入序号: "))
            if modify_choice not in [1, 2, 3]:
                print("无效输入")
                break
        except ValueError:
            print("无效输入")
            continue

        if modify_choice == 1:
            # 检查是否存在LobbyAvatarExtEffect.uasset文件
            res_path = find_battle_item(selected_folder, "LobbyAvatarExtEffect.uasset")
            res_path1 = find_battle_item(selected_folder, "BattleItem.uasset")
            if res_path == None:
                print(f"错误：LobbyAvatarExtEffect.uasset文件不存在,实体包不在这个pak文件中！")
                return
            battleitem_folder = os.path.join(selected_folder, os.path.dirname(res_path))
            battleitem_path = os.path.join(battleitem_folder, "LobbyAvatarExtEffect.uasset")
            help_path = os.path.join(battleitem_folder, "BattleItem.uasset")

            copy_file_auto_create(battleitem_path, os.path.join(BASE_PATH2, subfolders[choice], res_path))
            copy_file_auto_create(help_path, os.path.join(BASE_PATH2, subfolders[choice], res_path1))
            selected_folder = os.path.join(BASE_PATH2, subfolders[choice])
            battleitem_folder = os.path.join(selected_folder, os.path.dirname(res_path))
            battleitem_path = os.path.join(selected_folder, res_path)

            # 初始化内容变量
            modified_content = None
            modifications_made = False

            # 选择修改方式

            # 输入配置文件路径
            config_path = input("请输入配置文件路径: ").strip()
            if not os.path.exists(config_path):
                print("配置文件不存在")
                return

            # 如果是第一次修改，读取原始文件内容
            if modified_content is None:
                with open(battleitem_path, 'rb') as f:
                    modified_content = bytearray(f.read())

            # 执行修改
            success = False
            # print(battleitem_folder)
            modified_content, success = modify_mode_1(battleitem_folder, config_path,
                                                      current_content=modified_content)

            if success:
                modifications_made = True
                print("修改已应用到内存中")

        elif modify_choice == 2:
            # 检查是否存在ItemEmotionRefer.uasset文件
            res_path = find_battle_item(selected_folder, "ItemEmotionRefer.uasset")
            res_path1 = find_battle_item(selected_folder, "BattleItem.uasset")
            if res_path == None:
                print(f"错误：ItemEmotionRefer.uasset文件不存在,实体包不在这个pak文件中！")
                return
            battleitem_folder = os.path.join(selected_folder, os.path.dirname(res_path))
            battleitem_path = os.path.join(battleitem_folder, "ItemEmotionRefer.uasset")
            help_path = os.path.join(battleitem_folder, "BattleItem.uasset")

            copy_file_auto_create(battleitem_path, os.path.join(BASE_PATH2, subfolders[choice], res_path))
            copy_file_auto_create(help_path, os.path.join(BASE_PATH2, subfolders[choice], res_path1))
            selected_folder = os.path.join(BASE_PATH2, subfolders[choice])
            battleitem_folder = os.path.join(selected_folder, os.path.dirname(res_path))
            battleitem_path = os.path.join(selected_folder, res_path)

            # 初始化内容变量
            modified_content = None
            modifications_made = False

            # 选择修改方式

            # 输入配置文件路径
            config_path = input("请输入配置文件路径: ").strip()
            if not os.path.exists(config_path):
                print("配置文件不存在")
                return

            # 如果是第一次修改，读取原始文件内容
            if modified_content is None:
                with open(battleitem_path, 'rb') as f:
                    modified_content = bytearray(f.read())

            # 执行修改
            success = False
            print(battleitem_folder)
            modified_content, success = modify_mode_1(battleitem_folder, config_path,
                                                      current_content=modified_content)

            if success:
                modifications_made = True
                print("修改已应用到内存中")
        elif modify_choice == 3:
            # 检查是否存在DeadlistAndBox.uexp文件
            res_path = find_battle_item(selected_folder, "DeadlistAndBox.uexp")
            if res_path == None:
                print(f"错误：DeadlistAndBox.uexp文件不存在,实体包不在这个pak文件中！")
                return
            battleitem_folder = os.path.join(selected_folder, os.path.dirname(res_path))
            battleitem_path = os.path.join(battleitem_folder, "DeadlistAndBox.uexp")

            copy_file_auto_create(battleitem_path, os.path.join(BASE_PATH2, subfolders[choice], res_path))
            selected_folder = os.path.join(BASE_PATH2, subfolders[choice])
            battleitem_folder = os.path.join(selected_folder, os.path.dirname(res_path))
            battleitem_path = os.path.join(selected_folder, res_path)

            # 初始化内容变量
            modified_content = None
            modifications_made = False

            # 选择修改方式

            # 输入配置文件路径
            config_path = input("请输入配置文件路径: ").strip()
            if not os.path.exists(config_path):
                print("配置文件不存在")
                return

            # 如果是第一次修改，读取原始文件内容
            if modified_content is None:
                with open(battleitem_path, 'rb') as f:
                    modified_content = bytearray(f.read())

            # 执行修改
            success = False
            print(battleitem_folder)
            modified_content, success = modify_mode_2(battleitem_folder, config_path,
                                                      current_content=modified_content)

            if success:
                modifications_made = True
                print("修改已应用到内存中")

            # 是否继续修改
        continue_choice = input("\n是否继续修改？(y/n): ").strip().lower()
        if continue_choice != 'y':
            # 在退出循环后一次性写入文件
            if modifications_made and modified_content is not None:
                destination_file = os.path.join("./时雨自动/打包/", pakname, res_path)
                if write_to_destination(modified_content, destination_file):
                    print("所有修改已成功保存到：" + destination_file)
                destination_file = os.path.join("./时雨自动/制作区/", pakname, res_path)
                if write_to_destination(modified_content, destination_file):
                    print("所有修改已成功保存到：" + destination_file)
            return


###################################################A_Main_new###########################################################
###################################################A_Main_new###########################################################
###################################################A_Main_new###########################################################
###################################################A_Main_new###########################################################
###################################################A_Main_new###########################################################
def search_pak_files(base_path):
    """仅搜索指定根目录下的.pak文件（不包括子文件夹）"""
    pak_files = []
    # 只遍历base_path根目录，不递归子文件夹
    for file in os.listdir(base_path):
        file_path = os.path.join(base_path, file)
        # 检查是否为文件且以.pak结尾
        if os.path.isfile(file_path) and file.endswith(".pak"):
            pak_files.append(file_path)
    return pak_files


def create_base_folders(base_path, folder_names):
    """创建基础文件夹（打包、解包）"""
    for folder_name in folder_names:
        folder_path = os.path.join(base_path, folder_name)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)


def clear_directory_by_recreate(dir_path):
    if not os.path.exists(dir_path):
        print(f"目录不存在: {dir_path}")
        return False

    try:
        # 删除整个目录
        shutil.rmtree(dir_path)
        # 重新创建空目录
        os.makedirs(dir_path)
        print(f"已清空目录: {dir_path}")
        return True
    except Exception as e:
        print(f"清空目录失败: {e}")
        return False


def main():
    # ver = Verification()
    # if ver.newver() != "ok":
    #     os.system('pause')
    #     return
    # ver.register()
    # if not ver.Verify():
    #     return
    base_path = "./时雨自动"
    # base_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "时雨自动")
    # 基础文件夹包含制作区
    base_folder_names = ["打包", "解包", "制作区"]
    create_base_folders(base_path, base_folder_names)
    # 2. 用户选择操作（保留交互）
    while True:
        print(WATERMARK)
        print("╔════════════════════════╦══════════════════════════╗")
        print("║ 📂 基础功能            ║ 🛠️  高级修改             ║")
        print("╠════════════════════════╬══════════════════════════╣")
        print("║  [1] 解包操作          ║  [5] 地铁美化            ║")
        print("║  [2] 打包操作          ║  [6] 人物出场淘汰播报    ║")
        print("║  [3] 实体美化          ║  [7] 超广角 & 加速       ║")
        print("║  [4] 伪实体美化        ║  [8] 偷配置&代码提取     ║")
        print("║  [9] 清除所有修改      ║                          ║")
        print("╠════════════════════════╩══════════════════════════╣")
        print("║  [0] 退出程序                                     ║")
        print("╚═══════════════════════════════════════════════════╝")
        action_choice = None
        try:
            action_choice = input("请输入使用的功能:").strip()
        except KeyboardInterrupt:
            print("用户中断了程序")

        if action_choice not in [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9"
        ]:
            print("无效的操作选择。")
            continue
        if action_choice == "1" or action_choice == "2":
            pak_files = search_pak_files(base_path)
            if not pak_files:
                print(f"在 {base_path} 根目录下未找到任何.pak文件。")
                continue
                # 4. 用户选择要处理的pak文件
            print("找到以下.pak文件，请选择一个：")
            for idx, pak_file in enumerate(pak_files, start=1):
                print(f"{idx}. {pak_file}")

            try:
                choice = int(input("请输入数字选择一个文件："))
                selected_pak_file = pak_files[choice - 1]
            except (ValueError, IndexError):
                print("无效的选择，请重新输入。")
                continue
                # 5. 执行解包/打包

            if action_choice == "1":
                # 解包并获取路径和pak文件名
                file_name = os.path.splitext(os.path.basename(selected_pak_file))[0]  # 获取pak文件名（不含扩展名）
                unpack_path = os.path.join(base_path, "解包", file_name)
                if not os.path.exists(os.path.join(base_path, "打包")):
                    os.mkdir(os.path.join(base_path, "打包"))
                if not os.path.exists(os.path.join(base_path, "打包", file_name)):
                    os.mkdir(os.path.join(base_path, "打包", file_name))

                if not os.path.exists(os.path.join(base_path, "制作区")):
                    os.mkdir(os.path.join(base_path, "制作区"))
                if not os.path.exists(os.path.join(base_path, "制作区", file_name)):
                    os.mkdir(os.path.join(base_path, "制作区", file_name))
                tool = UE4PakEngine(selected_pak_file)
                if tool.parse():
                    tool.extract(unpack_path)
            else:
                # 打包操作
                file_name = os.path.splitext(os.path.basename(selected_pak_file))[0]  # 获取pak文件名（不含扩展名）
                tool = UE4PakEngine(selected_pak_file)
                repack_path = os.path.join(base_path, "打包", file_name)
                print(repack_path)
                if tool.parse():
                    tool.reimport(repack_path)
            continue
        elif action_choice == "3":
            C_STedit_new()
        elif action_choice == "4":
            D_WSTedit_new()
        elif action_choice == "5":
            E_DTedit_new()
        elif action_choice == "6":
            I_ClothApp_new()
        elif action_choice == "8":
            F_CodeExtract_new()
        elif action_choice == "7":
            H_WideAngle_new()
        elif action_choice == "9":
            continue_choice = input("是否确认删除？(y/n): ").strip().lower()
            if continue_choice != 'y':
                continue
            clear_directory_by_recreate(os.path.join(base_path, "制作区"))
            clear_directory_by_recreate(os.path.join(base_path, "打包"))


if __name__ == "__main__":
    main()
