# README

## 專案簡介

| 路徑                      | 說明                         |
| ------------------------- | ---------------------------- |
| `ApcDemo/`                | 測試 APC 觸發條件            |
| `meow_dll/`               | `meow_dll.dll` 原始碼        |
| `meowApp/`                | `meowApp.exe` 原始碼         |
| `TargetApp/`              | `TargetApp.exe` 原始碼       |
| `DLL_Injection/`          | DLL Injection PoC            |
| `EarlyBirdAPCInjection/`  | Early Bird APC Injection PoC |
| `ProcessHollowing/`       | Process Hollowing PoC        |
| `ReflectiveDLLInjection/` | Reflective DLL Injection PoC |

## Process Injection 說明

1. 將 `meow_dll.dll` 放在 `%TEMP%` 內
2. `EarlyBirdAPCInjection` 跟 `ProcessHollowing` 有路徑要設定
