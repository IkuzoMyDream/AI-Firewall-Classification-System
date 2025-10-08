# โครงสร้างโปรเจกต์ (Project Structure)

## ภาพรวม (Overview)
โครงงานนี้แบ่งเป็น 4 ส่วนหลัก: **การเก็บข้อมูล**, **การฝึกโมเดล**, **การจำแนกแบบเรียลไทม์**, และ **การตรวจสอบความแม่นยำ**

---

## โครงสร้างโฟลเดอร์ (Directory Layout)

```
AI-Firewall-Classification-System/
│
├── src/                          # ซอร์สโค้ดหลัก (Main Source Code)
│   ├── __init__.py              # Python package initializer
│   ├── data_collector.py        # [โมดูล 1] เก็บรวบรวมข้อมูลพฤติกรรมเครือข่าย
│   ├── train_model.py           # [โมดูล 2] ฝึกโมเดล AI และประเมินผล
│   ├── classify.py              # [โมดูล 3] จำแนกไฟร์วอลล์แบบเรียลไทม์
│   └── validate_model.py        # [โมดูล 4] ตรวจสอบความแม่นยำด้วยข้อมูลใหม่
│
├── data/                         # ข้อมูลทั้งหมด (Dataset Storage)
│   ├── raw/                     # ข้อมูลดิบจากการเก็บรวบรวม
│   └── processed/               # ข้อมูลที่ผ่านการประมวลผลแล้ว
│       └── dataset.csv          # ชุดข้อมูลสำหรับฝึกโมเดล (10 features + label)
│
├── models/                       # โมเดล AI ที่ฝึกเสร็จแล้ว (Trained Models)
│   └── firewall_classifier.pkl  # โมเดล Random Forest ที่บันทึกไว้
│
├── results/                      # ผลลัพธ์จากการฝึกและประเมินผล (Evaluation Results)
│   ├── confusion_matrices/      # กราฟ Confusion Matrix
│   │   └── confusion_matrix.png
│   └── metrics/                 # ค่าความแม่นยำและกราฟวิเคราะห์
│       ├── metrics.json         # Accuracy, Precision, Recall, F1-Score
│       ├── feature_importance.png
│       └── learning_curve.png
│
├── vm_configs/                   # การตั้งค่าไฟร์วอลล์บน VM (VM Configuration Files)
│   ├── VM1.txt                  # No Firewall (ไม่มีการกรอง)
│   ├── VM2.txt                  # Stateless Firewall (iptables)
│   ├── VM3.txt                  # Stateful Firewall (ufw)
│   └── VM4.txt                  # Proxy Firewall (Squid)
│
├── docs/                         # เอกสารประกอบ (Documentation)
│   ├── images/                  # รูปภาพประกอบ
│   │   └── image.png            # Network topology diagram
│   ├── feature.txt              # อธิบายฟีเจอร์แต่ละตัว
│   ├── payload.txt              # รายละเอียด network payloads
│   └── PROJECT_STRUCTURE.md    # ไฟล์นี้
│
├── examples/                     # ตัวอย่างการใช้งาน (Usage Examples)
│   ├── usage_examples.md
│   └── validation_example.md
│
├── requirements.txt              # Python dependencies
├── README.md                     # คู่มือหลักของโปรเจกต์
└── CONTRIBUTING.md              # แนวทางการมีส่วนร่วม

```

---

## รายละเอียดโมดูลหลัก (Core Modules)

### 1️⃣ `src/data_collector.py` — เก็บรวบรวมข้อมูลพฤติกรรมเครือข่าย
**หน้าที่:**
- ส่งคำสั่ง `ping`, `nmap`, `hping3`, `curl` ไปยังเครื่องเป้าหมาย (VM)
- สกัดค่า 10 ฟีเจอร์พฤติกรรม (Behavioral Features):
  - **Layer 3 (Network):** avg_latency, packet_loss, ttl_return, icmp_reachable
  - **Layer 4 (Transport):** filtered_ports_count, scan_time, syn_ack_ratio, tcp_reset_ratio
  - **Layer 7 (Application):** response_time, header_modified
- บันทึกเป็นไฟล์ CSV พร้อม label (0=No FW, 1=Stateless, 2=Stateful, 3=Proxy)

**การใช้งาน:**
```bash
# เก็บข้อมูล VM ทั้ง 4 เครื่อง จำนวน 250 ครั้งต่อเครื่อง
python src/data_collector.py \
  --targets 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13 \
  --label-map 192.168.56.10:0 192.168.56.11:1 192.168.56.12:2 192.168.56.13:3 \
  --repeat 250 \
  --output data/processed/dataset.csv
```

**ฟังก์ชันสำคัญ:**
- `collect_features(target_ip)` → รวบรวมฟีเจอร์ทั้งหมดจาก 1 เป้าหมาย
- `parse_ping()` → แปลงผล ping เป็น latency, packet_loss, TTL
- `parse_nmap()` → นับพอร์ตที่ filtered + วัดเวลาสแกน
- `parse_hping3()` → คำนวณ syn_ack_ratio, tcp_reset_ratio
- `parse_curl()` → วัด response_time + ตรวจ header_modified

---

### 2️⃣ `src/train_model.py` — ฝึกโมเดล AI และประเมินผล
**หน้าที่:**
- โหลดข้อมูลจาก `data/processed/dataset.csv`
- แบ่งข้อมูล 80% Train / 20% Test (Stratified Split)
- ฝึกโมเดล **Random Forest Classifier** (n_estimators=100, max_depth=10)
- ประเมินผลด้วย:
  - Accuracy, Precision, Recall, F1-Score
  - 5-Fold Cross-Validation (พิสูจน์ไม่ overfit)
  - Learning Curve (พิสูจน์เรียนรู้จริง ไม่จำแบบตายตัว)
- บันทึกโมเดลเป็น `models/firewall_classifier.pkl`
- สร้างกราฟ:
  - Confusion Matrix → `results/confusion_matrices/confusion_matrix.png`
  - Feature Importance → `results/metrics/feature_importance.png`
  - Learning Curve → `results/metrics/learning_curve.png`

**การใช้งาน:**
```bash
python src/train_model.py
```

**ฟังก์ชันสำคัญ:**
- `load_data()` → โหลด CSV และแยก X (features), y (labels)
- `train_model()` → ฝึก Random Forest
- `evaluate_model()` → คำนวณ metrics ทั้งหมด
- `cross_validate_model()` → ทดสอบ 5-Fold CV
- `plot_confusion_matrix()` → วาดกราฟ confusion matrix
- `plot_feature_importance()` → วาดกราฟความสำคัญของฟีเจอร์
- `plot_learning_curve()` → วาดกราฟ learning curve

---

### 3️⃣ `src/classify.py` — จำแนกไฟร์วอลล์แบบเรียลไทม์
**หน้าที่:**
- รับ IP address ของเครือข่ายที่ไม่รู้จัก
- เรียก `data_collector.collect_features()` เก็บข้อมูลพฤติกรรม
- โหลดโมเดลที่ฝึกไว้ (`firewall_classifier.pkl`)
- ทำนายประเภทไฟร์วอลล์ + แสดง Confidence (%)
- แสดงผลแบบมีสี (Color-coded Output)

**การใช้งาน:**
```bash
# จำแนกเครื่องเดียว
python src/classify.py 192.168.56.13

# จำแนกหลายเครื่อง
python src/classify.py 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13

# แสดง debug information
python src/classify.py 192.168.56.13 --debug
```

**ฟังก์ชันสำคัญ:**
- `load_model()` → โหลดโมเดลจากไฟล์ .pkl
- `classify_host(target_ip)` → เก็บ features + ทำนาย
- `print_result()` → แสดงผลลัพธ์แบบสวยงาม (พร้อมสี)

---

### 4️⃣ `src/validate_model.py` — ตรวจสอบความแม่นยำด้วยข้อมูลใหม่
**หน้าที่:**
- รับไฟล์ CSV ชุดใหม่ที่ไม่เคยเห็น (unseen data)
- โหลดโมเดลที่ฝึกไว้
- ทำนายและเปรียบเทียบกับ label จริง (ถ้ามี)
- แสดง Classification Report และ Confusion Matrix
- หากไม่มี label → บันทึกผลทำนายลงไฟล์ใหม่

**การใช้งาน:**
```bash
# เก็บข้อมูลชุดใหม่
python src/data_collector.py \
  --targets 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13 \
  --repeat 20 \
  --output validation_data.csv

# ตรวจสอบความแม่นยำ
python src/validate_model.py validation_data.csv
```

**ฟังก์ชันสำคัญ:**
- `load_model()` → โหลดโมเดล
- `validate_on_new_data()` → ทำนายและประเมินผล
- แสดง Accuracy, Precision, Recall, F1 per class
- แสดงรายการตัวอย่างที่ทำนายผิด (Misclassified Samples)

---

## การทำงานของระบบ (System Workflow)

```
┌─────────────────────────────────────────────────────────────────┐
│  1. การเก็บข้อมูล (Data Collection)                             │
│     data_collector.py → dataset.csv                             │
└───────────────────┬─────────────────────────────────────────────┘
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. การฝึกโมเดล (Model Training)                                │
│     train_model.py → firewall_classifier.pkl + metrics/plots    │
└───────────────────┬─────────────────────────────────────────────┘
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. การใช้งานจริง (Production Usage)                            │
│     classify.py → ทำนายไฟร์วอลล์ของ IP ใหม่                     │
└───────────────────┬─────────────────────────────────────────────┘
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. การตรวจสอบ (Validation)                                      │
│     validate_model.py → ทดสอบความแม่นยำด้วยข้อมูลใหม่           │
└─────────────────────────────────────────────────────────────────┘
```

---

## ไฟล์สำคัญอื่น ๆ (Additional Files)

| ไฟล์ | ประเภท | คำอธิบาย |
|------|--------|----------|
| `requirements.txt` | Config | รายการ Python packages ที่ต้องติดตั้ง |
| `README.md` | Doc | คู่มือหลัก ครอบคลุมทุกอย่างตั้งแต่ setup ถึง usage |
| `CONTRIBUTING.md` | Doc | แนวทางการมีส่วนร่วมในโปรเจกต์ |
| `data/processed/dataset.csv` | Data | ชุดข้อมูลฝึกหลัก (timestamp, host, 10 features, label) |
| `models/firewall_classifier.pkl` | Model | โมเดล Random Forest ที่ฝึกเสร็จแล้ว |
| `results/metrics/metrics.json` | Output | ค่า Accuracy, Precision, Recall, F1, CV scores |
| `vm_configs/*.txt` | Config | คำสั่งตั้งค่าไฟร์วอลล์บน VM แต่ละตัว |

---

## Dependencies (Python Packages)

```
scikit-learn   # Random Forest, Metrics, Cross-Validation
pandas         # Data manipulation
numpy          # Numerical operations
matplotlib     # Plotting graphs
seaborn        # Enhanced visualization
joblib         # Model serialization
```

ติดตั้ง:
```bash
pip install -r requirements.txt
```

---

## Network Tools (External Dependencies)

```
ping     # ICMP reachability test
nmap     # Port scanning
hping3   # TCP SYN/ACK probing
curl     # HTTP header analysis
```

ติดตั้ง (Kali/Ubuntu):
```bash
sudo apt update
sudo apt install -y nmap hping3 curl iputils-ping
```

---

## สรุป (Summary)

โครงสร้างถูกออกแบบให้:
- **แยกหน้าที่ชัดเจน** (Separation of Concerns): แต่ละโมดูลทำงานเฉพาะทาง
- **ทำซ้ำได้** (Reproducible): random_state คงที่, บันทึก logs ครบ
- **ขยายได้** (Scalable): เพิ่มฟีเจอร์/โมเดลใหม่โดยไม่กระทบโครงสร้างเดิม
- **อธิบายได้** (Explainable): มี Feature Importance + Confusion Matrix
- **พร้อมใช้งานจริง** (Production-ready): มีโมดูล classify + validate แยก

🎯 **จุดเด่น:** 
- ระบบอัตโนมัติตั้งแต่เก็บข้อมูล → ฝึก → ทำนาย → ตรวจสอบ
- ไม่ต้องแก้โค้ดเมื่อเพิ่มข้อมูล (เพียงรัน data_collector + train ใหม่)
- ทุกผลลัพธ์บันทึกไว้ใน `results/` ตรวจย้อนหลังได้
