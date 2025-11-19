# SOCify - منصة محاكاة مركز العمليات الأمنية

## نظرة عامة على المشروع

SOCify هي منصة شاملة ومتطورة لمحاكاة مركز العمليات الأمنية (Security Operations Center - SOC)، مصممة خصيصاً لتوفير بيئة تدريبية واقعية ومتطورة للمحللين الأمنيين ومديري SOC والمهتمين بتعلم الأمن السيبراني.

### المشكلة التي يحلها المشروع
يواجه تعليم الأمن السيبراني تحدياً كبيراً يتمثل في عدم توفر بيئات تدريبية عملية وآمنة للطلاب والمهنيين. معظم البرامج التعليمية تعتمد على المحاضرات النظرية دون إمكانية ممارسة المهارات العملية في بيئة واقعية.

### الحل المقدم
تقدم SOCify حلاً شاملاً لهذه المشاكل من خلال:
- **بيئة محاكاة واقعية**: تحاكي مركز العمليات الأمنية الحقيقي بجميع مكوناته
- **تدريب آمن**: لا توجد مخاطر على الأنظمة الحقيقية
- **تكلفة منخفضة**: متاحة للجميع دون تكلفة عالية
- **سهولة الوصول**: يمكن استخدامها من أي مكان وفي أي وقت

## الميزات الرئيسية للمنصة

### 🔐 نظام إدارة المستخدمين والأدوار المتقدم

#### أنواع المستخدمين المدعومة:

**1. المحلل الأمني (Security Analyst)**
- عرض وإدارة الأحداث الأمنية
- تحليل التهديدات والهجمات
- تحديث حالة الأحداث
- إضافة تعليقات وملاحظات

**2. مدير SOC (SOC Manager)**
- جميع صلاحيات المحلل
- إدارة القواعد والسياسات
- إدارة مصادر البيانات
- مراقبة أداء الفريق
- إنشاء التقارير

**3. مدير النظام (System Administrator)**
- جميع الصلاحيات
- إدارة المستخدمين والحسابات
- إعدادات النظام العامة
- عرض سجلات التدقيق الكاملة
- إدارة قاعدة البيانات

### 📊 نظام مراقبة الأحداث الأمنية المتطور

#### مصادر البيانات المدعومة:
- **جدران الحماية (Firewalls)**: استقبال سجلات حركة المرور
- **أنظمة كشف التسلل (IDS)**: تحليل الأنشطة المشبوهة
- **خوادم التطبيقات**: مراقبة أخطاء التطبيقات
- **خوادم قواعد البيانات**: تتبع محاولات الوصول غير المصرح بها
- **أنظمة التشغيل**: مراقبة أحداث النظام

#### تصنيف الأحداث:
- **حرج (Critical)**: يتطلب تدخل فوري
- **عالي (High)**: يحتاج اهتمام عاجل
- **متوسط (Medium)**: يحتاج مراجعة في الوقت المناسب
- **منخفض (Low)**: للمراقبة الروتينية

### ⚙️ محرك القواعد الذكي والأتمتة

#### أنواع القواعد المدعومة:
- **قواعد الكشف**: تحديد الأنشطة المشبوهة تلقائياً
- **قواعد الاستجابة**: تنفيذ إجراءات تلقائية عند حدوث أحداث معينة
- **قواعد التصعيد**: رفع مستوى الأحداث حسب الشروط المحددة
- **قواعد الإشعارات**: إرسال تنبيهات للمعنيين

### 🧪 مختبر المحاكاة الأمنية الشامل

#### أنواع الهجمات المحاكاة:

**1. هجمات حقن SQL (SQL Injection)**
- محاكاة محاولات اختراق قاعدة البيانات
- عرض البيانات الحساسة المسربة
- كشف نقاط الضعف في التطبيقات

**2. هجمات DDoS (Distributed Denial of Service)**
- محاكاة فيضان الشبكة
- مراقبة تأثير الهجمات على الخوادم
- تدريب على استراتيجيات التخفيف

**3. هجمات XSS (Cross-Site Scripting)**
- محاكاة حقن النصوص الضارة
- اختبار نقاط ضعف المتصفحات
- تدريب على تنظيف المدخلات

**4. هجمات القوة الغاشمة (Brute Force)**
- محاكاة محاولات كسر كلمات المرور
- مراقبة محاولات تسجيل الدخول الفاشلة
- تدريب على سياسات قفل الحسابات

**5. هجمات SSRF (Server-Side Request Forgery)**
- محاكاة مسح الشبكة الداخلية
- كشف الخدمات المخفية
- تدريب على منع الوصول غير المصرح

**6. هجمات DoS (Denial of Service)**
- محاكاة استنزاف الموارد
- مراقبة توفر الخدمات
- تدريب على إجراءات الاسترداد

**7. هجمات التصيد (Phishing)**
- محاكاة رسائل البريد الإلكتروني المزيفة
- تدريب على كشف محاولات التصيد
- فهم تقنيات الهندسة الاجتماعية

**8. هجمات MITM (Man-in-the-Middle)**
- محاكاة اعتراض الاتصالات
- كشف محاولات التنصت
- تدريب على الاتصال الآمن

**9. هجمات CSRF (Cross-Site Request Forgery)**
- محاكاة الإجراءات غير المصرح بها
- تدريب على حماية النماذج
- فهم آليات المصادقة

**10. هجمات Directory Traversal**
- محاكاة الوصول غير المصرح للملفات
- كشف نقاط ضعف نظام الملفات
- تدريب على التحقق من المسارات

**11. هجمات Command Injection**
- محاكاة تنفيذ الأوامر الضارة
- كشف نقاط ضعف معالجة المدخلات
- تدريب على تنظيف البيانات

## التقنيات المستخدمة في التطوير

### تقنيات الخادم الخلفي (Backend)

#### Python 3.8+
```python
# مثال على استخدام Python في المشروع
import sqlite3
import json
import uuid
import datetime
import bcrypt
import os
from functools import wraps
import logging
```

#### Flask 2.3.3
```python
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'socify-secret-key-change-in-production'
app.config['DATABASE'] = 'socify.db'

# Initialize extensions
CORS(app, origins=['http://localhost:5000', 'http://127.0.0.1:5000'])
csrf = CSRFProtect(app)
```

#### SQLite Database
```python
def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn
```

#### bcrypt للتشفير
```python
# تشفير كلمة المرور
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# التحقق من كلمة المرور
if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
    # تسجيل الدخول ناجح
```

### تقنيات الواجهة الأمامية (Frontend)

#### HTML5 مع دعم RTL
```html
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>لوحة التحكم - SOCify</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
```

#### CSS3 مع متغيرات مخصصة
```css
/* CSS Variables for SOCify Color Palette */
:root {
    /* Background Colors */
    --bg-primary: #0D0D0D;
    --bg-secondary: #1A1A1A;
    --bg-tertiary: #2A2A2A;

    /* Primary Colors */
    --primary: #1565C0;
    --primary-light: #1976D2;
    --primary-dark: #0D47A1;

    /* Event Severity Colors */
    --severity-critical: #FF1744;
    --severity-high: #FF9100;
    --severity-medium: #29B6F6;
    --severity-low: #76FF03;
}
```

#### JavaScript ES6+ للمحاكاة
```javascript
// Global variables for simulations
let simulations = {
    sql: { running: false, interval: null },
    ddos: { running: false, interval: null },
    xss: { running: false, interval: null },
    brute: { running: false, interval: null },
    ssrf: { running: false, interval: null },
    dos: { running: false, interval: null },
    phishing: { running: false, interval: null },
    mitm: { running: false, interval: null },
    csrf: { running: false, interval: null },
    dirTraversal: { running: false, interval: null },
    cmdInjection: { running: false, interval: null }
};

// Initialize lab when page loads
document.addEventListener('DOMContentLoaded', function () {
    initializeLab();
    addLogEntry('تم تحميل مختبر المحاكاة الأمنية بنجاح');
});
```

## هيكل المشروع والملفات

### 📁 هيكل المشروع الكامل
```
SOCify/
├── 📄 app.py                          # التطبيق الرئيسي Flask
├── 📄 run.py                          # ملف تشغيل التطبيق
├── 📄 create_db.py                     # سكريبت إنشاء قاعدة البيانات
├── 📄 requirements.txt                 # متطلبات المشروع
├── 📄 socify.db                        # قاعدة البيانات SQLite
├── 📄 README.md                        # دليل المشروع
├── 📁 templates/                       # قوالب HTML
│   ├── 📄 index.html                   # الصفحة الرئيسية
│   ├── 📄 login.html                   # صفحة تسجيل الدخول
│   ├── 📄 register.html                # صفحة التسجيل
│   ├── 📄 dashboard.html               # لوحة التحكم الرئيسية
│   ├── 📄 lab.html                     # مختبر المحاكاة الأمنية
│   ├── 📄 rules.html                   # إدارة القواعد
│   ├── 📄 profile.html                 # الملف الشخصي
│   ├── 📄 events.html                  # إدارة الأحداث الأمنية
│   ├── 📄 users.html                   # إدارة المستخدمين
│   └── 📄 audit.html                   # سجلات التدقيق
├── 📁 static/                          # الملفات الثابتة
│   ├── 📁 css/                         # ملفات الأنماط
│   │   ├── 📄 style.css                # الأنماط الرئيسية
│   │   ├── 📄 normalize.css            # إعادة تعيين الأنماط
│   │   ├── 📄 dashboard.css            # أنماط لوحة التحكم
│   │   ├── 📄 lab.css                  # أنماط مختبر المحاكاة
│   │   ├── 📄 auth.css                 # أنماط صفحات المصادقة
│   │   └── 📄 responsive.css            # التصميم المتجاوب
│   ├── 📁 js/                          # ملفات JavaScript
│   │   ├── 📄 main.js                  # الوظائف الرئيسية
│   │   ├── 📄 dashboard.js             # وظائف لوحة التحكم
│   │   ├── 📄 lab.js                   # وظائف مختبر المحاكاة
│   │   ├── 📄 auth.js                  # وظائف المصادقة
│   │   ├── 📄 profile.js               # وظائف الملف الشخصي
│   │   ├── 📄 events.js                # وظائف إدارة الأحداث
│   │   ├── 📄 rules.js                 # وظائف إدارة القواعد
│   │   └── 📄 utils.js                 # وظائف مساعدة
│   ├── 📁 images/                      # الصور والأيقونات
│   │   ├── 📄 logo.svg                 # شعار SOCify
│   │   ├── 📄 favicon.ico              # أيقونة الموقع
│   │   ├── 📄 security-icons/          # أيقونات الأمان
│   │   └── 📄 backgrounds/             # خلفيات الصفحات
│   └── 📁 fonts/                       # الخطوط
│       └── 📄 ibm-plex-sans-arabic/    # خط IBM Plex Sans Arabic
├── 📁 docs/                            # الوثائق
│   ├── 📄 installation.md              # دليل التثبيت
│   ├── 📄 user-guide.md                # دليل المستخدم
│   ├── 📄 api-documentation.md          # وثائق API
│   └── 📄 security-guide.md            # دليل الأمان
├── 📁 tests/                           # الاختبارات
│   ├── 📄 test_app.py                  # اختبارات التطبيق
│   ├── 📄 test_auth.py                 # اختبارات المصادقة
│   ├── 📄 test_database.py             # اختبارات قاعدة البيانات
│   └── 📄 test_simulations.py          # اختبارات المحاكاة
├── 📁 logs/                            # ملفات السجلات
│   ├── 📄 app.log                      # سجل التطبيق
│   ├── 📄 error.log                    # سجل الأخطاء
│   └── 📄 audit.log                    # سجل التدقيق
├── 📁 config/                          # ملفات التكوين
│   ├── 📄 config.py                    # إعدادات التطبيق
│   ├── 📄 database.py                   # إعدادات قاعدة البيانات
│   └── 📄 security.py                  # إعدادات الأمان
├── 📁 migrations/                      # ملفات الهجرة
│   ├── 📄 001_initial_schema.sql       # المخطط الأولي
│   ├── 📄 002_add_audit_logs.sql       # إضافة سجلات التدقيق
│   └── 📄 003_add_simulation_data.sql  # إضافة بيانات المحاكاة
├── 📁 scripts/                         # السكريبتات المساعدة
│   ├── 📄 backup.py                    # سكريبت النسخ الاحتياطي
│   ├── 📄 restore.py                   # سكريبت الاسترداد
│   ├── 📄 cleanup.py                   # سكريبت التنظيف
│   └── 📄 maintenance.py               # سكريبت الصيانة
└── 📁 data/                            # البيانات التجريبية
    ├── 📄 sample_events.json           # أحداث تجريبية
    ├── 📄 sample_users.json            # مستخدمين تجريبيين
    ├── 📄 sample_rules.json            # قواعد تجريبية
    └── 📄 simulation_scenarios.json    # سيناريوهات المحاكاة
```

### 📂 شرح المجلدات والملفات

#### 📄 الملفات الجذرية (Root Files)
- **`app.py`**: التطبيق الرئيسي Flask مع جميع المسارات والوظائف
- **`run.py`**: سكريبت تشغيل التطبيق مع فحص المتطلبات وإنشاء قاعدة البيانات
- **`create_db.py`**: سكريبت إنشاء قاعدة البيانات مع الجداول والبيانات التجريبية
- **`requirements.txt`**: قائمة جميع المكتبات المطلوبة مع الأصدارات المحددة
- **`socify.db`**: قاعدة البيانات SQLite (يتم إنشاؤها تلقائياً)
- **`README.md`**: دليل المشروع الشامل

#### 📁 مجلد القوالب (Templates/)
يحتوي على جميع صفحات HTML مع دعم كامل للغة العربية واتجاه RTL:

- **`index.html`**: الصفحة الرئيسية مع مقدمة عن المنصة وميزاتها
- **`login.html`**: صفحة تسجيل الدخول مع التحقق من البيانات
- **`register.html`**: صفحة التسجيل مع فحص التكرار والتحقق
- **`dashboard.html`**: لوحة التحكم الرئيسية مع الإحصائيات والأحداث
- **`lab.html`**: مختبر المحاكاة الأمنية مع 11 نوع هجوم مختلف
- **`rules.html`**: إدارة القواعد مع إنشاء وتعديل القواعد
- **`profile.html`**: الملف الشخصي مع تعديل البيانات وكلمة المرور
- **`events.html`**: إدارة الأحداث الأمنية مع الفلترة والبحث
- **`users.html`**: إدارة المستخدمين (للمديرين فقط)
- **`audit.html`**: سجلات التدقيق مع البحث والفلترة

#### 📁 مجلد الملفات الثابتة (Static/)

##### 📁 CSS/ - ملفات الأنماط
- **`style.css`**: الأنماط الرئيسية مع متغيرات CSS المخصصة
- **`normalize.css`**: إعادة تعيين الأنماط الافتراضية للمتصفحات
- **`dashboard.css`**: أنماط خاصة بلوحة التحكم والعناصر التفاعلية
- **`lab.css`**: أنماط مختبر المحاكاة مع تأثيرات بصرية متقدمة
- **`auth.css`**: أنماط صفحات المصادقة والتسجيل
- **`responsive.css`**: التصميم المتجاوب لجميع أحجام الشاشات

##### 📁 JS/ - ملفات JavaScript
- **`main.js`**: الوظائف الرئيسية المشتركة بين جميع الصفحات
- **`dashboard.js`**: وظائف لوحة التحكم مع التحديث التلقائي
- **`lab.js`**: وظائف مختبر المحاكاة مع 11 نوع هجوم مختلف
- **`auth.js`**: وظائف المصادقة مع التحقق من البيانات
- **`profile.js`**: وظائف الملف الشخصي مع تعديل البيانات
- **`events.js`**: وظائف إدارة الأحداث مع الفلترة والبحث
- **`rules.js`**: وظائف إدارة القواعد مع إنشاء وتعديل القواعد
- **`utils.js`**: وظائف مساعدة مشتركة بين جميع الملفات

##### 📁 Images/ - الصور والأيقونات
- **`logo.svg`**: شعار SOCify بتصميم أمني متطور
- **`favicon.ico`**: أيقونة الموقع في تبويب المتصفح
- **`security-icons/`**: مجموعة أيقونات الأمان والتهديدات
- **`backgrounds/`**: خلفيات الصفحات بتصميم أمني

##### 📁 Fonts/ - الخطوط
- **`ibm-plex-sans-arabic/`**: خط IBM Plex Sans Arabic لدعم اللغة العربية

#### 📁 مجلد الوثائق (Docs/)
- **`installation.md`**: دليل التثبيت المفصل مع المتطلبات
- **`user-guide.md`**: دليل المستخدم مع شرح جميع الميزات
- **`api-documentation.md`**: وثائق API مع أمثلة الاستخدام
- **`security-guide.md`**: دليل الأمان والميزات الأمنية

#### 📁 مجلد الاختبارات (Tests/)
- **`test_app.py`**: اختبارات التطبيق الرئيسي والمسارات
- **`test_auth.py`**: اختبارات المصادقة وتسجيل الدخول
- **`test_database.py`**: اختبارات قاعدة البيانات والعمليات
- **`test_simulations.py`**: اختبارات المحاكاة والهجمات

#### 📁 مجلد السجلات (Logs/)
- **`app.log`**: سجل التطبيق مع جميع العمليات
- **`error.log`**: سجل الأخطاء للمراجعة والتطوير
- **`audit.log`**: سجل التدقيق مع جميع العمليات الحساسة

#### 📁 مجلد التكوين (Config/)
- **`config.py`**: إعدادات التطبيق العامة
- **`database.py`**: إعدادات قاعدة البيانات والاتصال
- **`security.py`**: إعدادات الأمان والتشفير

#### 📁 مجلد الهجرة (Migrations/)
- **`001_initial_schema.sql`**: المخطط الأولي لقاعدة البيانات
- **`002_add_audit_logs.sql`**: إضافة جداول سجلات التدقيق
- **`003_add_simulation_data.sql`**: إضافة بيانات المحاكاة التجريبية

#### 📁 مجلد السكريبتات (Scripts/)
- **`backup.py`**: سكريبت النسخ الاحتياطي لقاعدة البيانات
- **`restore.py`**: سكريبت الاسترداد من النسخ الاحتياطية
- **`cleanup.py`**: سكريبت تنظيف الملفات المؤقتة والسجلات القديمة
- **`maintenance.py`**: سكريبت الصيانة الدورية للنظام

#### 📁 مجلد البيانات (Data/)
- **`sample_events.json`**: أحداث أمنية تجريبية للاختبار
- **`sample_users.json`**: مستخدمين تجريبيين مع أدوار مختلفة
- **`sample_rules.json`**: قواعد تجريبية للكشف والاستجابة
- **`simulation_scenarios.json`**: سيناريوهات محاكاة متقدمة

### الملفات الرئيسية

#### `app.py` - التطبيق الرئيسي
```python
# إعداد Flask والتطبيق
app = Flask(__name__)
app.config['SECRET_KEY'] = 'socify-secret-key-change-in-production'
app.config['DATABASE'] = 'socify.db'

# تعريف المسارات
@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/lab')
@login_required
def lab():
    """Security simulation lab"""
    return render_template('lab.html')
```

#### `create_db.py` - إنشاء قاعدة البيانات
```python
def create_database():
    """Create SOCify database with all tables and sample data"""
    
    # Remove existing database if it exists
    if os.path.exists('socify.db'):
        os.remove('socify.db')
        print("تم حذف قاعدة البيانات الموجودة")
    
    # Create new database
    conn = sqlite3.connect('socify.db')
    conn.row_factory = sqlite3.Row
    
    # Create tables
    conn.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'analyst' CHECK (role IN ('analyst', 'soc_manager', 'admin')),
            team VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
```

#### `run.py` - ملف التشغيل
```python
#!/usr/bin/env python3
"""
SOCify - SOC Simulation Platform
Run this script to start the application
"""

import os
import sys

def main():
    print("🚀 بدء تشغيل SOCify...")
    
    # Check if we're in the right directory
    if not os.path.exists('app.py'):
        print("❌ خطأ: يجب تشغيل السكريبت من مجلد SOCify")
        return
    
    # Check if database exists, if not create it
    if not os.path.exists('socify.db'):
        print("📊 إنشاء قاعدة البيانات...")
        try:
            from app import init_db
            init_db()
        except Exception as e:
            print(f"❌ خطأ في إنشاء قاعدة البيانات: {e}")
            return
    
    # Start the Flask application
    print("🌐 بدء تشغيل الخادم...")
    print("📍 العنوان: http://localhost:5000")
    print("🔑 بيانات الدخول:")
    print("   مدير النظام: admin@socify.local / admin123")
    print("   محلل أمني: analyst1@socify.local / password123")
    print("   مدير SOC: manager@socify.local / password123")
```

### مجلد القوالب (Templates)

#### `dashboard.html` - لوحة التحكم
```html
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>لوحة التحكم - SOCify</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}">
</head>

<body class="dashboard-body">
    <header class="dashboard-header">
        <div class="header-left">
            <div class="logo">
                <div class="logo-icon">
                    <svg viewBox="0 0 100 100" width="32" height="32">
                        <path d="M50 10 L80 30 L80 70 L50 90 L20 70 L20 30 Z" fill="none" stroke="#1565C0" stroke-width="3" />
                        <circle cx="50" cy="50" r="15" fill="#00E5FF" />
                        <circle cx="50" cy="50" r="8" fill="#1565C0" />
                    </svg>
                </div>
                <span class="logo-text">SOCify</span>
            </div>
        </div>
        
        <div class="header-center">
            <h1 class="dashboard-title">مركز عمليات الأمن السيبراني</h1>
        </div>
        
        <div class="header-right">
            <div class="user-menu">
                <div class="user-info">
                    <span class="user-name">{{ session.user_name }}</span>
                    <span class="user-role">{{ session.user_role|getRoleName }}</span>
                </div>
            </div>
        </div>
    </header>
</body>
</html>
```

#### `lab.html` - مختبر المحاكاة
```html
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>مختبر المحاكاة - SOCify</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/lab.css') }}">
</head>

<body class="dashboard-body">
    <header class="dashboard-header">
        <div class="header-center">
            <h1 class="dashboard-title">مختبر المحاكاة الأمنية</h1>
        </div>
    </header>

    <div class="lab-container">
        <div class="simulation-grid">
            <div class="simulation-card" data-simulation="sql">
                <div class="card-header">
                    <h3>SQL Injection</h3>
                    <div class="severity-badge critical">حرج</div>
                </div>
                <div class="card-content">
                    <p>محاكاة هجمات حقن SQL على قاعدة البيانات</p>
                    <div class="simulation-controls">
                        <button class="btn btn-danger" onclick="toggleSimulation('sql')">
                            <span class="btn-text">بدء المحاكاة</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="{{ url_for('static', filename='js/lab.js') }}"></script>
</body>
</html>
```

### مجلد الملفات الثابتة (Static)

#### `static/css/style.css` - الأنماط الرئيسية
```css
/* SOCify Main Stylesheet - Cybersecurity Theme */

/* CSS Variables for SOCify Color Palette */
:root {
    /* Background Colors */
    --bg-primary: #0D0D0D;
    --bg-secondary: #1A1A1A;
    --bg-tertiary: #2A2A2A;

    /* Primary Colors */
    --primary: #1565C0;
    --primary-light: #1976D2;
    --primary-dark: #0D47A1;

    /* Secondary Colors */
    --secondary: #00E5FF;
    --secondary-light: #26C6DA;
    --secondary-dark: #00BCD4;

    /* Event Severity Colors */
    --severity-critical: #FF1744;
    --severity-high: #FF9100;
    --severity-medium: #29B6F6;
    --severity-low: #76FF03;

    /* Status Colors */
    --status-open: #FFC107;
    --status-investigating: #FF9800;
    --status-resolved: #4CAF50;
    --status-false-positive: #9E9E9E;
}

/* Base Styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'IBM Plex Sans Arabic', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    direction: rtl;
    text-align: right;
}

/* Button Styles */
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    text-decoration: none;
    cursor: pointer;
    transition: all 0.3s ease;
    gap: 8px;
}

.btn-primary {
    background: linear-gradient(135deg, var(--primary), var(--primary-light));
    color: white;
}

.btn-danger {
    background: linear-gradient(135deg, var(--severity-critical), #D32F2F);
    color: white;
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px var(--shadow-primary);
}
```

#### `static/js/lab.js` - وظائف مختبر المحاكاة
```javascript
// SOCify Lab JavaScript - Professional Implementation

// Global variables
let simulations = {
    sql: { running: false, interval: null },
    ddos: { running: false, interval: null },
    xss: { running: false, interval: null },
    brute: { running: false, interval: null },
    ssrf: { running: false, interval: null },
    dos: { running: false, interval: null },
    phishing: { running: false, interval: null },
    mitm: { running: false, interval: null },
    csrf: { running: false, interval: null },
    dirTraversal: { running: false, interval: null },
    cmdInjection: { running: false, interval: null }
};

// Initialize lab when page loads
document.addEventListener('DOMContentLoaded', function () {
    initializeLab();
    addLogEntry('تم تحميل مختبر المحاكاة الأمنية بنجاح');
});

// Initialize lab components
function initializeLab() {
    setupSimulationCards();
    updateAllMetrics();
    setupRealTimeMonitoring();
    updateStatistics();
}

// Setup simulation cards
function setupSimulationCards() {
    const cards = document.querySelectorAll('.simulation-card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function () {
            this.style.transform = 'translateY(-4px)';
        });

        card.addEventListener('mouseleave', function () {
            this.style.transform = 'translateY(0)';
        });
    });
}

// Toggle simulation
function toggleSimulation(simulationType) {
    const simulation = simulations[simulationType];
    const button = document.querySelector(`[data-simulation="${simulationType}"] .btn`);
    
    if (simulation.running) {
        stopSimulation(simulationType);
        button.innerHTML = '<span class="btn-text">بدء المحاكاة</span>';
        button.classList.remove('btn-success');
        button.classList.add('btn-danger');
    } else {
        startSimulation(simulationType);
        button.innerHTML = '<span class="btn-text">إيقاف المحاكاة</span>';
        button.classList.remove('btn-danger');
        button.classList.add('btn-success');
    }
}

// Start simulation
function startSimulation(simulationType) {
    simulations[simulationType].running = true;
    addLogEntry(`بدأت محاكاة ${simulationType.toUpperCase()}`);
    
    // Start simulation-specific logic
    switch(simulationType) {
        case 'sql':
            startSQLInjectionSimulation();
            break;
        case 'ddos':
            startDDOSSimulation();
            break;
        case 'xss':
            startXSSSimulation();
            break;
        // ... other simulations
    }
}

// Stop simulation
function stopSimulation(simulationType) {
    simulations[simulationType].running = false;
    if (simulations[simulationType].interval) {
        clearInterval(simulations[simulationType].interval);
        simulations[simulationType].interval = null;
    }
    addLogEntry(`توقفت محاكاة ${simulationType.toUpperCase()}`);
}

// SQL Injection Simulation
function startSQLInjectionSimulation() {
    simulations.sql.interval = setInterval(() => {
        if (simulations.sql.running) {
            // Simulate SQL injection attempts
            const attacks = [
                "SELECT * FROM users WHERE id = 1 OR 1=1",
                "DROP TABLE users; --",
                "UNION SELECT password FROM admin_users",
                "'; DELETE FROM logs; --"
            ];
            
            const randomAttack = attacks[Math.floor(Math.random() * attacks.length)];
            addLogEntry(`محاولة حقن SQL: ${randomAttack}`, 'critical');
            updateMetrics('sql_attempts', 1);
        }
    }, 3000);
}

// DDoS Simulation
function startDDOSSimulation() {
    simulations.ddos.interval = setInterval(() => {
        if (simulations.ddos.running) {
            // Simulate DDoS attack
            const requests = Math.floor(Math.random() * 1000) + 500;
            addLogEntry(`هجوم DDoS: ${requests} طلب في الثانية`, 'critical');
            updateMetrics('ddos_requests', requests);
        }
    }, 2000);
}

// Add log entry
function addLogEntry(message, severity = 'info') {
    const logContainer = document.getElementById('log-container');
    if (logContainer) {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${severity}`;
        logEntry.innerHTML = `
            <span class="log-time">${new Date().toLocaleTimeString('ar-SA')}</span>
            <span class="log-message">${message}</span>
        `;
        logContainer.insertBefore(logEntry, logContainer.firstChild);
        
        // Keep only last 50 entries
        while (logContainer.children.length > 50) {
            logContainer.removeChild(logContainer.lastChild);
        }
    }
}

// Update metrics
function updateMetrics(metric, value) {
    const metricElement = document.getElementById(metric);
    if (metricElement) {
        const currentValue = parseInt(metricElement.textContent) || 0;
        metricElement.textContent = currentValue + value;
    }
}
```

## قاعدة البيانات وهيكل البيانات

### الجداول الرئيسية

#### جدول المستخدمين (users)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'analyst' CHECK (role IN ('analyst', 'soc_manager', 'admin')),
    team VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active INTEGER DEFAULT 1
);
```

#### جدول الأحداث الأمنية (security_events)
```sql
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(50) UNIQUE NOT NULL,
    source VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    category VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    raw_data TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    assigned_to INTEGER,
    created_by INTEGER,
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### جدول القواعد (rules)
```sql
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    condition_type VARCHAR(100) NOT NULL,
    condition_value TEXT NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    action_value TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### جدول سجلات التدقيق (audit_logs)
```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action VARCHAR(100) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    record_id INTEGER,
    old_values TEXT,
    new_values TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## الميزات الأمنية المتقدمة

### حماية كلمات المرور
```python
# تشفير كلمة المرور عند التسجيل
def register_user(email, password, name, team):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    conn = get_db_connection()
    cursor = conn.execute('''
        INSERT INTO users (email, password_hash, name, role, team)
        VALUES (?, ?, ?, 'analyst', ?)
    ''', (email, password_hash, name, team))
    conn.commit()
    conn.close()

# التحقق من كلمة المرور عند تسجيل الدخول
def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
```

### حماية من هجمات CSRF
```python
from flask_wtf.csrf import CSRFProtect

# إعداد حماية CSRF
csrf = CSRFProtect(app)

# في القوالب HTML
<meta name="csrf-token" content="{{ csrf_token() }}">

# في JavaScript
const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
```

### التحقق من المدخلات
```python
def validate_input(data):
    """Validate and sanitize input data"""
    if not data:
        return None
    
    # Remove potentially dangerous characters
    sanitized = data.strip()
    sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
    sanitized = sanitized.replace('"', '&quot;').replace("'", '&#x27;')
    
    return sanitized

# استخدام في API endpoints
@app.route('/api/events', methods=['POST'])
@login_required
def create_event():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['source', 'severity', 'category', 'title', 'description']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Sanitize input
    title = validate_input(data['title'])
    description = validate_input(data['description'])
    
    # Create event with sanitized data
    # ...
```

### إدارة الجلسات الآمنة
```python
def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('login'))
            
            conn = get_db_connection()
            user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            
            if not user or user['role'] not in required_role:
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('Insufficient permissions', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
```

### سجل التدقيق الشامل
```python
def log_audit(user_id, action, table_name, record_id=None, old_values=None, new_values=None):
    """Log audit trail"""
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO audit_logs (user_id, action, table_name, record_id, old_values, new_values, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, action, table_name, record_id, old_values, new_values, 
          request.remote_addr, request.headers.get('User-Agent')))
    conn.commit()
conn.close()

# استخدام في العمليات الحساسة
@app.route('/api/events/<int:event_id>', methods=['PUT'])
@login_required
def update_event(event_id):
    data = request.get_json()
    
    conn = get_db_connection()
    current_event = conn.execute('SELECT * FROM security_events WHERE id = ?', (event_id,)).fetchone()
    
    # Update event
    # ... update logic ...
    
    # Log the change
    log_audit(session['user_id'], 'update', 'security_events', event_id, 
              json.dumps(dict(current_event)), json.dumps(data))
    
    conn.close()
    return jsonify({'message': 'Event updated successfully'})
```

## واجهة المستخدم وتجربة المستخدم

### التصميم المتجاوب
```css
/* Responsive Design */
@media (max-width: 768px) {
    .dashboard-container {
        flex-direction: column;
    }
    
    .sidebar {
        width: 100%;
        height: auto;
        position: relative;
    }
    
    .main-content {
        width: 100%;
        margin-right: 0;
    }
}

@media (max-width: 480px) {
    .dashboard-header {
        flex-direction: column;
        gap: 16px;
    }
    
    .header-center {
        order: -1;
    }
    
    .simulation-grid {
        grid-template-columns: 1fr;
    }
}
```

### دعم اللغة العربية
```css
/* RTL Support */
body {
    direction: rtl;
    text-align: right;
}

.sidebar-nav {
    text-align: right;
}

.log-entry {
    direction: rtl;
    text-align: right;
}

/* Arabic Font */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@100;200;300;400;500;600;700&display=swap');

body {
    font-family: 'IBM Plex Sans Arabic', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}
```

### نظام الألوان المتطور
```css
/* Event Severity Colors */
.severity-critical {
    background-color: var(--severity-critical);
    color: white;
}

.severity-high {
    background-color: var(--severity-high);
    color: white;
}

.severity-medium {
    background-color: var(--severity-medium);
    color: white;
}

.severity-low {
    background-color: var(--severity-low);
    color: black;
}

/* Status Colors */
.status-open {
    background-color: var(--status-open);
    color: black;
}

.status-investigating {
    background-color: var(--status-investigating);
    color: white;
}

.status-resolved {
    background-color: var(--status-resolved);
    color: white;
}

.status-false-positive {
    background-color: var(--status-false-positive);
    color: white;
}
```

## الأداء والتحسين

### تحسين قاعدة البيانات
```python
# إنشاء الفهارس لتحسين الأداء
def create_indexes():
    conn = get_db_connection()
    
    # Indexes for better performance
    conn.execute('CREATE INDEX idx_users_email ON users(email)')
    conn.execute('CREATE INDEX idx_users_role ON users(role)')
    conn.execute('CREATE INDEX idx_events_severity ON security_events(severity)')
    conn.execute('CREATE INDEX idx_events_status ON security_events(status)')
    conn.execute('CREATE INDEX idx_events_timestamp ON security_events(timestamp)')
    conn.execute('CREATE INDEX idx_events_source ON security_events(source)')
    conn.execute('CREATE INDEX idx_audit_logs_user ON audit_logs(user_id)')
    conn.execute('CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp)')
    
    conn.commit()
    conn.close()
```

### تحسين الواجهة الأمامية
```javascript
// تحميل تدريجي للمحتوى
function loadContentLazily() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                loadContent(entry.target);
                observer.unobserve(entry.target);
            }
        });
    });
    
    document.querySelectorAll('.lazy-content').forEach(el => {
        observer.observe(el);
    });
}

// ذاكرة تخزين مؤقت للبيانات
const cache = new Map();

function getCachedData(key) {
    if (cache.has(key)) {
        return cache.get(key);
    }
    return null;
}

function setCachedData(key, data, ttl = 300000) { // 5 minutes
    cache.set(key, {
        data: data,
        timestamp: Date.now(),
        ttl: ttl
    });
}
```

## التطوير المستقبلي

### الميزات المخططة
- **تكامل الذكاء الاصطناعي**: استخدام AI لكشف التهديدات المتقدمة
- **تحليلات متقدمة**: تقارير وتحليلات أكثر تفصيلاً
- **دعم السحابة**: نشر المنصة على السحابة
- **تطبيق الهاتف المحمول**: تطبيق مخصص للهواتف الذكية

### التحسينات التقنية
- **هندسة الخدمات المصغرة**: تقسيم التطبيق إلى خدمات صغيرة
- **قاعدة بيانات متقدمة**: استخدام PostgreSQL أو MySQL
- **ذاكرة تخزين مؤقت متقدمة**: استخدام Redis أو Memcached
- **مراقبة متقدمة**: أدوات مراقبة شاملة للنظام

## الخلاصة

SOCify هي منصة شاملة ومتطورة لمحاكاة مركز العمليات الأمنية، تجمع بين التقنيات الحديثة والتصميم المتطور لتقديم تجربة تعليمية فريدة ومفيدة. المنصة توفر:

### المميزات الرئيسية:
- **بيئة محاكاة واقعية** تحاكي مركز العمليات الأمنية الحقيقي
- **نظام إدارة مستخدمين متطور** مع ثلاثة مستويات من الصلاحيات
- **مراقبة الأحداث في الوقت الفعلي** مع تصنيف ذكي للخطورة
- **محرك قواعد ذكي** للأتمتة والكشف التلقائي
- **مختبر محاكاة شامل** مع 11 نوع مختلف من الهجمات
- **واجهة مستخدم متطورة** مع دعم كامل للغة العربية
- **أمان متقدم** مع حماية شاملة من الهجمات
- **أداء محسن** مع تحميل سريع واستجابة فورية

### الفوائد التعليمية:
- **سد الفجوة بين النظرية والتطبيق** في تعليم الأمن السيبراني
- **توفير بيئة آمنة** للتدريب دون مخاطر على الأنظمة الحقيقية
- **تكلفة منخفضة** مقارنة بالتدريب التقليدي
- **سهولة الوصول** من أي مكان وفي أي وقت
- **قابلية التوسع** لاستيعاب أعداد كبيرة من الطلاب

SOCify تمثل نقلة نوعية في تعليم الأمن السيبراني، وتوفر الأساس القوي لتطوير جيل جديد من المهنيين المهرة في مجال الأمن السيبراني.

## إعداد وتشغيل المشروع على البيئة المحلية

### 🛠️ إعداد البيئة المحلية

#### 1. إعداد Python البيئة الافتراضية (Virtual Environment)

**إنشاء البيئة الافتراضية:**

#### 1. تثبيت المتطلبات

**تحديث pip:**
```bash
python -m pip install --upgrade pip
```

**تثبيت المكتبات المطلوبة:**
```bash
# تثبيت جميع المتطلبات من ملف requirements.txt
pip install -r requirements.txt

# أو تثبيت المكتبات واحدة تلو الأخرى
pip install Flask==2.3.3
pip install Flask-CORS==4.0.0
pip install Flask-WTF==1.1.1
pip install WTForms==3.0.1
pip install bcrypt==4.0.1
pip install python-dotenv==1.0.0
pip install Werkzeug==2.3.7
pip install SQLAlchemy==2.0.21
pip install Flask-SQLAlchemy==3.0.5
```

**التحقق من التثبيت:**
```bash
pip list
```

#### 2. إعداد قاعدة البيانات

**إنشاء قاعدة البيانات:**
```bash
# تشغيل سكريبت إنشاء قاعدة البيانات
python create_db.py
```

**التحقق من إنشاء قاعدة البيانات:**
```bash
# يجب أن تظهر ملف socify.db في المجلد
ls socify.db  # في Linux/Mac
dir socify.db  # في Windows
```

### 🚀 تشغيل المشروع

#### الطريقة الأولى: التشغيل السريع

**تشغيل مع سكريبت run.py:**
```bash
# تأكد من تفعيل البيئة الافتراضية أولاً
python run.py
```

**التحقق من التشغيل:**
```bash
# يجب أن تظهر رسائل مثل:
# 🚀 بدء تشغيل SOCify...
# 📊 إنشاء قاعدة البيانات...
# 🌐 بدء تشغيل الخادم...
# 📍 العنوان: http://localhost:5000
```

#### الطريقة الثانية: التشغيل اليدوي

**تشغيل Flask مباشرة:**
```bash
# تشغيل التطبيق
python app.py

# أو
flask run
```

**تشغيل مع خيارات متقدمة:**
```bash
# تشغيل مع منفذ مخصص
python app.py --port 8080

# تشغيل مع عنوان IP مخصص
python app.py --host 0.0.0.0 --port 5000
```

#### الطريقة الثالثة: تشغيل مع Flask CLI

**إعداد متغيرات البيئة:**
```bash
# في Windows
set FLASK_APP=app.py
set FLASK_ENV=development
set FLASK_DEBUG=1

# في Linux/Mac
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_DEBUG=1
```

**تشغيل مع Flask CLI:**
```bash
flask run
```

### 🌐 الوصول للمنصة

#### 1. الوصول المحلي
- **الرابط الرئيسي**: `http://localhost:5000`
- **الرابط البديل**: `http://127.0.0.1:5000`

#### 2. الوصول من نفس الشبكة
```bash
# معرفة عنوان IP
ipconfig  # في Windows
ifconfig  # في Linux/Mac

# الوصول من أجهزة أخرى
http://192.168.1.100:5000  # استبدل بالIP الفعلي
```

#### 3. اختبار الاتصال
```bash
# اختبار الاتصال مع curl
curl http://localhost:5000

# أو مع ping
ping localhost
```

### 🔑 بيانات الدخول الافتراضية

بعد تشغيل المشروع بنجاح، استخدم الحسابات التالية:

#### مدير النظام (System Administrator)
```
البريد الإلكتروني: admin@socify.local
كلمة المرور: admin123
الصلاحيات: جميع الصلاحيات - إدارة المستخدمين، النظام، قاعدة البيانات
```

#### مدير SOC (SOC Manager)
```
البريد الإلكتروني: manager@socify.local
كلمة المرور: password123
الصلاحيات: إدارة القواعد، الأحداث، الفريق، التقارير
```

#### محلل أمني (Security Analyst)
```
البريد الإلكتروني: analyst1@socify.local
كلمة المرور: password123
الصلاحيات: عرض وإدارة الأحداث الأمنية، التحليل، التعليقات
```

### 🔧 استكشاف الأخطاء وإصلاحها

#### مشاكل شائعة وحلولها

**1. خطأ في البيئة الافتراضية:**
```bash
# إعادة إنشاء البيئة الافتراضية
rm -rf socify_env  # في Linux/Mac
rmdir /s socify_env  # في Windows

python -m venv socify_env
source socify_env/bin/activate  # في Linux/Mac
socify_env\Scripts\activate  # في Windows
```

**2. خطأ في تثبيت المكتبات:**
```bash
# تحديث pip
python -m pip install --upgrade pip

# تثبيت المكتبات مع إصدارات محددة
pip install Flask==2.3.3 --no-cache-dir
pip install Flask-CORS==4.0.0 --no-cache-dir
pip install bcrypt==4.0.1 --no-cache-dir
```

**3. خطأ في قاعدة البيانات:**
```bash
# حذف قاعدة البيانات الموجودة
rm socify.db  # في Linux/Mac
del socify.db  # في Windows

# إعادة إنشاء قاعدة البيانات
python create_db.py
```

**4. خطأ في المنفذ:**
```bash
# البحث عن العمليات التي تستخدم المنفذ 5000
netstat -ano | findstr :5000  # في Windows
lsof -i :5000  # في Linux/Mac

# إنهاء العملية
taskkill /PID <PID> /F  # في Windows
kill -9 <PID>  # في Linux/Mac
```

**5. خطأ في الصلاحيات:**
```bash
# في Linux/Mac، إعطاء صلاحيات التنفيذ
chmod +x run.py
chmod +x create_db.py
chmod +x app.py
```

### 📊 مراقبة التشغيل

#### 1. مراقبة السجلات
```bash
# مراقبة سجلات التطبيق في الوقت الفعلي
tail -f logs/app.log  # في Linux/Mac

# في Windows
type logs\app.log
```

#### 2. مراقبة الأداء
```bash
# مراقبة استخدام الذاكرة
ps aux | grep python  # في Linux/Mac
tasklist | findstr python  # في Windows
```

#### 3. مراقبة قاعدة البيانات
```bash
# فحص قاعدة البيانات
sqlite3 socify.db ".tables"
sqlite3 socify.db "SELECT COUNT(*) FROM users;"
sqlite3 socify.db "SELECT COUNT(*) FROM security_events;"
```

### 🔄 إيقاف وإعادة تشغيل المشروع

#### إيقاف المشروع
```bash
# في Terminal/Command Prompt
Ctrl + C

# أو إنهاء العملية
pkill -f "python app.py"  # في Linux/Mac
taskkill /f /im python.exe  # في Windows
```

#### إعادة تشغيل المشروع
```bash
# إعادة تشغيل سريع
python run.py

# إعادة تشغيل مع تنظيف
python create_db.py
python app.py
```

### 📝 ملاحظات مهمة للتطوير المحلي

1. **البيئة الافتراضية**: استخدم دائماً بيئة افتراضية لتجنب تضارب المكتبات
2. **النسخ الاحتياطي**: احتفظ بنسخة احتياطية من قاعدة البيانات قبل التطوير
3. **السجلات**: راقب سجلات التطبيق للكشف عن الأخطاء
4. **الأمان**: لا تستخدم كلمات المرور الافتراضية في الإنتاج
5. **التحديثات**: حافظ على تحديث المكتبات والمكتبات الأمنية

## طريقة تشغيل المشروع

### 📋 المتطلبات الأساسية

#### 1. متطلبات النظام
- **Python 3.8+**: إصدار حديث من Python
- **pip**: مدير حزم Python
- **Git**: لإستنساخ المشروع (اختياري)
- **متصفح حديث**: Chrome, Firefox, Safari, Edge

#### 2. متطلبات Python
```bash
# التحقق من إصدار Python
python --version
# أو
python3 --version

# التحقق من pip
pip --version
# أو
pip3 --version
```

### 🚀 خطوات التثبيت والتشغيل

#### الطريقة الأولى: التشغيل السريع

**1. تحميل المشروع**
```bash
# إذا كان المشروع على GitHub
git clone https://github.com/username/SOCify.git
cd SOCify

# أو تحميل الملفات مباشرة
# استخرج الملفات في مجلد SOCify
```

**2. تثبيت المتطلبات**
```bash
# تثبيت جميع المكتبات المطلوبة
pip install -r requirements.txt

# أو استخدام pip3
pip3 install -r requirements.txt
```

**3. تشغيل المشروع**
```bash
# الطريقة السريعة
python run.py

# أو
python3 run.py
```

**4. الوصول للمنصة**
- افتح المتصفح واذهب إلى: `http://localhost:5000`
- أو: `http://127.0.0.1:5000`

#### الطريقة الثانية: التشغيل اليدوي

**1. إنشاء قاعدة البيانات**
```bash
# تشغيل سكريبت إنشاء قاعدة البيانات
python create_db.py

# أو
python3 create_db.py
```

**2. تشغيل التطبيق**
```bash
# تشغيل Flask مباشرة
python app.py

# أو
python3 app.py
```

**3. الوصول للمنصة**
- افتح المتصفح واذهب إلى: `http://localhost:5000`

### 🔑 بيانات الدخول الافتراضية

بعد تشغيل المشروع، يمكنك استخدام الحسابات التالية:

#### مدير النظام (System Administrator)
```
البريد الإلكتروني: admin@socify.local
كلمة المرور: admin123
الصلاحيات: جميع الصلاحيات
```

#### مدير SOC (SOC Manager)
```
البريد الإلكتروني: manager@socify.local
كلمة المرور: password123
الصلاحيات: إدارة القواعد والأحداث والفريق
```

#### محلل أمني (Security Analyst)
```
البريد الإلكتروني: analyst1@socify.local
كلمة المرور: password123
الصلاحيات: عرض وإدارة الأحداث الأمنية
```

### 🛠️ إعدادات متقدمة

#### 1. تغيير المنفذ (Port)
```python
# في ملف app.py
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)  # تغيير المنفذ إلى 8080
```

#### 2. تشغيل في وضع الإنتاج
```python
# في ملف app.py
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # إيقاف وضع التطوير
```

#### 3. تغيير مفتاح الأمان
```python
# في ملف app.py
app.config['SECRET_KEY'] = 'your-secret-key-here'  # تغيير مفتاح الأمان
```

### 🔧 استكشاف الأخطاء وإصلاحها

#### مشاكل شائعة وحلولها

**1. خطأ في تثبيت المكتبات**
```bash
# تحديث pip أولاً
python -m pip install --upgrade pip

# تثبيت المكتبات واحدة تلو الأخرى
pip install Flask==2.3.3
pip install Flask-CORS==4.0.0
pip install Flask-WTF==1.1.1
pip install bcrypt==4.0.1
```

**2. خطأ في قاعدة البيانات**
```bash
# حذف قاعدة البيانات الموجودة
rm socify.db  # في Linux/Mac
del socify.db  # في Windows

# إعادة إنشاء قاعدة البيانات
python create_db.py
```

**3. خطأ في المنفذ المستخدم**
```bash
# البحث عن العمليات التي تستخدم المنفذ 5000
netstat -ano | findstr :5000  # في Windows
lsof -i :5000  # في Linux/Mac

# إنهاء العملية أو استخدام منفذ آخر
```

**4. خطأ في الصلاحيات**
```bash
# في Linux/Mac، إعطاء صلاحيات التنفيذ
chmod +x run.py
chmod +x create_db.py
```

### 📱 الوصول من أجهزة أخرى

#### 1. الوصول من نفس الشبكة
```python
# في ملف app.py
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)  # السماح بالوصول من أي IP
```

**الوصول من أجهزة أخرى:**
- من الهاتف: `http://192.168.1.100:5000` (استبدل بالIP الفعلي)
- من التابلت: `http://192.168.1.100:5000`
- من حاسوب آخر: `http://192.168.1.100:5000`

#### 2. معرفة عنوان IP
```bash
# في Windows
ipconfig

# في Linux/Mac
ifconfig
# أو
ip addr show
```

### 🔄 النسخ الاحتياطي والاسترداد

#### 1. النسخ الاحتياطي
```bash
# نسخ قاعدة البيانات
cp socify.db backup_socify_$(date +%Y%m%d_%H%M%S).db

# نسخ المشروع كاملاً
tar -czf SOCify_backup_$(date +%Y%m%d_%H%M%S).tar.gz SOCify/
```

#### 2. الاسترداد
```bash
# استرداد قاعدة البيانات
cp backup_socify_20231201_120000.db socify.db

# استرداد المشروع
tar -xzf SOCify_backup_20231201_120000.tar.gz
```

### 🚀 نشر المشروع على السحابة

#### 1. نشر على Heroku
```bash
# تثبيت Heroku CLI
# إنشاء ملف Procfile
echo "web: python app.py" > Procfile

# إنشاء ملف runtime.txt
echo "python-3.8.10" > runtime.txt

# نشر المشروع
heroku create socify-app
git push heroku main
```

#### 2. نشر على DigitalOcean
```bash
# رفع الملفات عبر SCP
scp -r SOCify/ user@server:/var/www/

# تشغيل على الخادم
ssh user@server
cd /var/www/SOCify
python3 app.py
```

### 📊 مراقبة الأداء

#### 1. مراقبة استخدام الذاكرة
```python
# إضافة في app.py
import psutil
import os

@app.route('/api/system-info')
def system_info():
    return jsonify({
        'memory_usage': psutil.virtual_memory().percent,
        'cpu_usage': psutil.cpu_percent(),
        'disk_usage': psutil.disk_usage('/').percent
    })
```

#### 2. مراقبة قاعدة البيانات
```python
# إضافة في app.py
@app.route('/api/db-stats')
def db_stats():
    conn = get_db_connection()
    stats = {
        'users_count': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'events_count': conn.execute('SELECT COUNT(*) FROM security_events').fetchone()[0],
        'rules_count': conn.execute('SELECT COUNT(*) FROM rules').fetchone()[0]
    }
    conn.close()
    return jsonify(stats)
```

### 🔐 أمان الإنتاج

#### 1. تغيير كلمات المرور الافتراضية
```python
# في create_db.py، تغيير كلمات المرور
admin_password = bcrypt.hashpw('your-secure-password'.encode('utf-8'), bcrypt.gensalt())
manager_password = bcrypt.hashpw('your-secure-password'.encode('utf-8'), bcrypt.gensalt())
analyst_password = bcrypt.hashpw('your-secure-password'.encode('utf-8'), bcrypt.gensalt())
```

#### 2. إعداد HTTPS
```python
# في app.py
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')
```

#### 3. إعداد جدار الحماية
```bash
# في Linux
sudo ufw allow 5000
sudo ufw enable

# في Windows
# إضافة قاعدة في Windows Firewall للسماح بالمنفذ 5000
```

### 📝 ملاحظات مهمة

1. **أمان قاعدة البيانات**: تأكد من تغيير كلمات المرور الافتراضية في الإنتاج
2. **النسخ الاحتياطي**: قم بعمل نسخ احتياطية دورية لقاعدة البيانات
3. **التحديثات**: حافظ على تحديث المكتبات والمكتبات الأمنية
4. **المراقبة**: راقب أداء النظام واستخدام الموارد
5. **السجلات**: راجع سجلات النظام بانتظام للكشف عن المشاكل

### 🆘 الدعم والمساعدة

إذا واجهت أي مشاكل في التشغيل:

1. **تحقق من المتطلبات**: تأكد من تثبيت Python 3.8+ وجميع المكتبات
2. **راجع السجلات**: تحقق من رسائل الخطأ في Terminal/Command Prompt
3. **اختبر الاتصال**: تأكد من أن المنفذ 5000 متاح
4. **أعد تشغيل النظام**: جرب إعادة تشغيل التطبيق أو النظام
5. **اتصل بالدعم**: إذا استمرت المشكلة، اتصل بفريق الدعم
