"""Catalog downloaded archives, without extracting or executing sample payloads.

Requires py7zr; used only for archive metadata and separating original handouts.
"""
from pathlib import Path
import hashlib
import json
import py7zr

ROOT = Path(__file__).resolve().parents[1] / 'datasets' / 'reverse-challenges'
SPECS = [
    ('01-x', 'X', 'X.7z', '入门', '.NET / MonoGame', ['字符串定位', '事件回调与口令判断']),
    ('02-itsonfire', 'ItsOnFire', 'ItsOnFire.7z', '初级', 'Android APK / Kotlin', ['Manifest 入口', '资源引用', 'CRC32 与 AES']),
    ('03-mypassion', 'Mypassion', 'mypassion.7z', '中高级', 'Windows 原生程序', ['多阶段输入约束', '结构体恢复', '嵌入代码与密码算法']),
    ('04-aimbot', 'Aimbot', 'aimbot.7z', '高级', 'Windows EXE / DLL', ['反调试', '环境依赖', '多阶段载荷']),
    ('05-where-am-i', 'Where_am_i', 'where_am_i.7z', '高级', 'Windows 原生程序', ['自修改代码', '反射加载', 'RC6']),
    ('12-hvm', 'HVM', 'hvm.7z', '挑战级', 'Windows x64 / Hyper-V', ['16/32/64 位切换', '虚拟机退出', '加密校验']),
]

def main():
    handouts = ROOT / 'challenges'
    with py7zr.SevenZipFile(ROOT / 'archives/Flare-On10_Challenges.7z', password='flare') as archive:
        archive.extract(path=handouts, targets=[s[2] for s in SPECS])
    rows = []
    for order, (cid, title, name, difficulty, platform, topics) in enumerate(SPECS, 1):
        folder = handouts / cid
        folder.mkdir(exist_ok=True)
        original = handouts / name
        target = folder / name
        if target.exists():
            if original.read_bytes() != target.read_bytes():
                raise ValueError(f'Existing handout differs: {target}')
            original.unlink()
        else:
            original.rename(target)
        with py7zr.SevenZipFile(target, password='flare') as archive:
            members = [{'path': f.filename, 'bytes': f.uncompressed, 'directory': f.is_directory}
                       for f in archive.list()]
        (folder / 'archive-members.json').write_text(json.dumps(members, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        rows.append(dict(id=cid, title=title, suggested_order=order, difficulty=difficulty,
                         platform=platform, topics=topics, archive=target.relative_to(ROOT).as_posix(),
                         archive_password='flare', source_member=name,
                         solution=f'references/{cid}/official-solution.pdf',
                         status='collected_not_tested', executed=False,
                         answer_source='official_author_solution', locally_validated=False))
    (ROOT / 'manifest.json').write_text(json.dumps(dict(
        schema_version=1, collected_on='2026-09-22', source='https://www.flare-on.com/',
        solution_index='https://cloud.google.com/blog/topics/threat-intelligence/flareon10-challenge-solutions/',
        scope='download_and_catalog_only', runtime_imported=False,
        difficulty_note='Local suggested progression, not an official rating; challenge 3 is a significant jump.',
        challenges=rows), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    for row in rows:
        print(row['id'], row['archive'])

if __name__ == '__main__':
    main()
