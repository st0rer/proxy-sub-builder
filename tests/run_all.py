#!/usr/bin/env python3
"""Главный запуск тестов и стресс-тестирование конвейера на масштабе 5 000+ нод."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import find_free_vpn as ffv
import scan_any as sa
import sb_verify as sbv


def run_unit_tests():
    print("=" * 60)
    print("1. ЗАПУСК ЮНИТ-ТЕСТОВ (UNIT TESTS)")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.dirname(__file__), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


def run_scale_stress_test(n_nodes=5000):
    print("\n" + "=" * 60)
    print(f"2. МАСШТАБНЫЙ СТРЕСС-ТЕСТ (SCALE STRESS TEST: {n_nodes} НОД)")
    print("=" * 60)

    # Генерация синтетического пула нод с дубликатами, CDN-фронтингом, разными протоколами
    print(f"Генерация {n_nodes} синтетических нод (VLESS, Hy2, SS, Trojan, Reality)...")
    synthetic_links = []
    base_uuids = [
        "11111111-2222-3333-4433-555555555555",
        "22222222-3333-4433-5555-666666666666",
        "33333333-4444-5555-6666-777777777777",
    ]
    cdn_ips = ["104.16.1.1", "104.16.2.2", "188.114.96.1", "172.67.1.1"]

    for i in range(n_nodes):
        proto = i % 4
        host = cdn_ips[i % len(cdn_ips)] if i % 2 == 0 else f"node-{i % 200}.server.com"
        port = 443 if i % 2 == 0 else 8443
        uuid = base_uuids[i % len(base_uuids)]

        if proto == 0:
            # VLESS Reality
            flow = "xtls-rprx-vision" if i % 5 != 0 else "xtls-rprx-vision-udp443"  # намеренно подмешиваем битый flow
            l = f"vless://{uuid}@{host}:{port}?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=&sid=123456&sni=dl{i%50}.google.com&flow={flow}#Node_{i}"
        elif proto == 1:
            # VLESS WS CDN
            l = f"vless://{uuid}@{host}:{port}?security=tls&sni=cdn{i%30}.example.com&type=ws&path=/vless{i%10}#Node_{i}"
        elif proto == 2:
            # Hysteria2
            l = f"hysteria2://password_{i%50}@{host}:{port}/?sni=hy2_{i%20}.org#Node_{i}"
        else:
            # Shadowsocks
            l = f"ss://YWVzLTEyOC1nY206cGFzczEyMw==@{host}:8388#SS_{i}"

        synthetic_links.append(l)

    # 1. Замер скорости экстракции
    t0 = time.time()
    raw_text = "\n".join(synthetic_links)
    extracted = ffv.extract_links(raw_text)
    t_extract = time.time() - t0
    print(f"-> Извлечение ссылок: {len(extracted)} за {t_extract:.3f} с ({len(extracted)/max(t_extract, 0.001):.0f} нод/сек)")

    # 2. Замер дедупликации
    t0 = time.time()
    deduped = sa.dedupe_connections(extracted)
    t_dedup = time.time() - t0
    print(f"-> Дедупликация: {len(extracted)} -> {len(deduped)} за {t_dedup:.3f} с ({len(extracted)/max(t_dedup, 0.001):.0f} нод/сек)")

    # 3. Замер сборки конфигурации sing-box (с отсевом битых flow)
    t0 = time.time()
    cfg, meta = sbv.build(deduped)
    t_build = time.time() - t0
    outbounds_cnt = len(cfg.get("outbounds", []))
    print(f"-> Сборка sing-box конфига: {outbounds_cnt} outbounds за {t_build:.3f} с ({len(deduped)/max(t_build, 0.001):.0f} нод/сек)")

    # Валидация: убеждаемся, что ни один битый flow не проник в конфигурацию
    for ob in cfg.get("outbounds", []):
        flow = ob.get("flow", "")
        if flow:
            assert flow == "xtls-rprx-vision", f"КРИТИЧЕСКАЯ ОШИБКА: обнаружен битый flow: {flow}"

    print(f"-> Защита flow: Все битые flow успешно отсеяны, конфиг безопасен для sing-box.")
    print("=" * 60)
    print("СТРЕСС-ТЕСТ УСПЕШНО ПРОЙДЕН!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    ok1 = run_unit_tests()
    if not ok1:
        print("Юнит-тесты провалились!")
        sys.exit(1)
    ok2 = run_scale_stress_test(5000)
    if not ok2:
        print("Стресс-тест провалился!")
        sys.exit(1)
    print("\nИТОГ: ВСЕ ТЕСТЫ ПРОЙДЕНЫ НА 100%!")
