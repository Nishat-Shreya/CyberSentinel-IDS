#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <stdexcept>
#include <ctime>
#include <iomanip>
#include <utility>
#include <memory>
#include <chrono>
#include <cstdio>   

using namespace std;

// ===================== UI / Color helpers =====================
namespace ui {
    const string RESET   = "\033[0m";
    const string BOLD    = "\033[1m";
    const string RED     = "\033[31m";
    const string GREEN   = "\033[32m";
    const string YELLOW  = "\033[33m";
    const string BLUE    = "\033[34m";
    const string CYAN    = "\033[36m";
    const string MAGENTA = "\033[35m";

    void printHeader() {
        auto now = chrono::system_clock::now();
        time_t t = chrono::system_clock::to_time_t(now);
        tm *tmv = localtime(&t);

        // Build digital clock string
        ostringstream oss;
        oss << put_time(tmv, "%Y-%m-%d %H:%M:%S");
        string timeStr = oss.str();
        const int WIDTH = 70;
        int padding = max(0, WIDTH - (int)timeStr.size());

        cout << BOLD << YELLOW << string(padding, ' ') << timeStr << RESET << "\n";

        cout << BOLD << CYAN;
        cout << "============================================================\n";
        cout << ui::BOLD << ui::RED
             << "                  CyberSentinel "
             << ui::CYAN << "IDS"
             << ui::MAGENTA << " Console"
             << ui::RESET << "\n";
        cout << ui::BOLD << ui::CYAN;
        cout << "============================================================\n";
        cout << RESET << "\n";
    }

    void pause() {
        cout << CYAN << "\nPress ENTER to continue..." << RESET;
        string dummy;
        getline(cin, dummy);
    }
}

// ===================== utils =====================
namespace utils {
    time_t parseTimestamp(const string &s) {
        tm tmv{};
        istringstream iss(s);
        iss >> get_time(&tmv, "%Y-%m-%d %H:%M:%S");
        if (iss.fail()) {
            throw runtime_error("Timestamp parse error: " + s);
        }
        tmv.tm_isdst = -1;
        return mktime(&tmv);
    }

    string formatTimestamp(time_t t) {
        tm *tmv = localtime(&t);
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tmv);
        return string(buf);
    }

    vector<string> splitCSV(const string &line) {
        vector<string> out;
        string cur;
        istringstream ss(line);
        while (getline(ss, cur, ',')) {
            size_t a = cur.find_first_not_of(" \t\r\n");
            size_t b = cur.find_last_not_of(" \t\r\n");
            out.push_back(a == string::npos ? "" : cur.substr(a, b - a + 1));
        }
        return out;
    }

    // Function template: generic filter
    template<typename T, typename Pred>
    vector<T> filter(const vector<T> &v, Pred p) {
        vector<T> out;
        out.reserve(v.size());
        for (const auto &e: v)
            if (p(e)) out.push_back(e);
        return out;
    }

    // Another function template: groupBy
    template<typename T, typename KeyFn>
    auto groupBy(const vector<T> &v, KeyFn keyFn) {
        using Key = decltype(keyFn(declval<T>()));
        map<Key, vector<T>> m;
        for (const auto &e: v) m[keyFn(e)].push_back(e);
        return m;
    }
}

// ===================== Class template: Repository<T> =====================
template<typename T>
class Repository {
    vector<T> items;
public:
    void add(const T &t) { items.push_back(t); }
    size_t size() const { return items.size(); }
    const vector<T> &getAll() const { return items; }

    const T &get(size_t index) const {
        if (index >= items.size()) throw out_of_range("Repository index out of range");
        return items[index];
    }
    const T &get() const {
        if (items.empty()) throw out_of_range("Repository is empty");
        return items.back();
    }

    ~Repository() = default;
};

// ===================== Abstract & multiple-inheritance helpers =====================
class Printable {
public:
    virtual void printPretty() const = 0;
    virtual ~Printable() = default;
};

class Timestamped {
protected:
    time_t createdAt{};
public:
    Timestamped() { createdAt = time(nullptr); }
    virtual ~Timestamped() = default;
    time_t getCreatedAt() const { return createdAt; }
};

// ===================== core classes =====================
class LogEntry {
    time_t timestamp{};
    string user;
    string action;
    string status;
public:
    LogEntry() = default;
    LogEntry(time_t ts, string u, string a, string s)
            : timestamp(ts), user(std::move(u)), action(std::move(a)), status(std::move(s)) {}
    virtual ~LogEntry() = default;

    time_t getTimestamp() const { return timestamp; }
    const string &getUser() const { return user; }
    const string &getAction() const { return action; }
    const string &getStatus() const { return status; }

    void setTimestamp(time_t t) { timestamp = t; }
    void setUser(const string &u) { user = u; }
    void setAction(const string &a) { action = a; }
    void setStatus(const string &s) { status = s; }

    virtual void display() const {
        cout << "[" << utils::formatTimestamp(timestamp) << "] "
             << user << " " << action << " " << status << "\n";
    }
};

class SecurityLog : public LogEntry, public Printable {
    string ip;
    int severity{1};
public:
    SecurityLog() = default;
    SecurityLog(time_t ts, string user, string action,
                string status, string ip, int sev) {
        setTimestamp(ts);
        setUser(user);
        setAction(action);
        setStatus(status);
        this->ip = std::move(ip);
        this->severity = sev;
    }

    const string &getIP() const { return ip; }
    int getSeverity() const { return severity; }

    bool operator<(const SecurityLog &other) const {
        if (severity != other.severity) return severity > other.severity; // higher first
        return getTimestamp() < other.getTimestamp();
    }

    explicit operator int() const { return severity; }

    void display() const override {
        cout << "[" << utils::formatTimestamp(getTimestamp()) << "] "
             << getUser() << "@" << ip << " "
             << getAction() << "/" << getStatus()
             << " sev=" << severity << "\n";
    }

    void printPretty() const override {
        cout << ui::YELLOW << "[LOG] " << getUser() << "@" << ip
             << " action=" << getAction()
             << " status=" << getStatus()
             << " severity=" << severity
             << ui::RESET << "\n";
    }
};

class PrivilegedLog : public SecurityLog {
    bool isRootAction{false};
public:
    PrivilegedLog(time_t ts, const string &user, const string &action,
                  const string &status, const string &ip, int sev)
        : SecurityLog(ts, user, action, status, ip, sev) {
        isRootAction = (user == "root");
    }
    ~PrivilegedLog() override = default;
};

class Alert {
    string message;
    string user;
    string ip;
    int severity{1};
    time_t firstSeen{};
    time_t lastSeen{};
public:
    Alert() = default;
    Alert(string msg, string u, string i, int sev, time_t f, time_t l)
            : message(std::move(msg)),
              user(std::move(u)),
              ip(std::move(i)),
              severity(sev),
              firstSeen(f),
              lastSeen(l) {}

    string toString() const {
        return string("[ALERT] ") + message + "\nUser: " + user +
               "\nIP: " + ip +
               "\nSeverity: " + to_string(severity) +
               "\nFirst: " + utils::formatTimestamp(firstSeen) +
               "\nLast:  " + utils::formatTimestamp(lastSeen) + "\n";
    }

    friend ostream &operator<<(ostream &os, const Alert &a) {
        return os << a.toString();
    }

    explicit operator int() const { return severity; }
    int getSeverity() const { return severity; }
};

// ===================== Rules =====================
class Rule {
public:
    virtual ~Rule() = default;
    virtual string name() const = 0;
    virtual void configure(const string &line) = 0;
    virtual vector<Alert> evaluate(const vector<SecurityLog> &logs) const = 0;
};

class ThresholdRule : public Rule {
    string targetAction{"LOGIN"};
    string targetStatus{"FAILED"};
    int windowSeconds{120};
    int threshold{5};
public:
    string name() const override { return "ThresholdRule"; }

    void configure(const string &line) override {
        auto p = utils::splitCSV(line);
        if (p.size() >= 5) {
            targetAction   = p[1];
            targetStatus   = p[2];
            windowSeconds  = stoi(p[3]);
            threshold      = stoi(p[4]);
        }
    }

    vector<Alert> evaluate(const vector<SecurityLog> &logs) const override {
        vector<Alert> alerts;

        map<string, vector<const SecurityLog *>> byKey;
        for (const auto &l: logs) {
            if (l.getAction() == targetAction && l.getStatus() == targetStatus) {
                byKey[l.getUser() + "|" + l.getIP()].push_back(&l);
            }
        }

        for (auto &kv: byKey) {
            auto &vec = kv.second;
            sort(vec.begin(), vec.end(),
                 [](const SecurityLog *a, const SecurityLog *b) {
                     return a->getTimestamp() < b->getTimestamp();
                 });

            size_t i = 0;
            while (i < vec.size()) {
                size_t j = i;
                while (j < vec.size() &&
                       (vec[j]->getTimestamp() - vec[i]->getTimestamp()) <= windowSeconds) {
                    j++;
                }

                int cnt = static_cast<int>(j - i);
                if (cnt >= threshold) {
                    const auto *f = vec[i];
                    const auto *l = vec[j - 1];
                    string msg = string("Suspicious Activity Detected!\nAction: ")
                                 + targetAction + " (" + targetStatus + ") x"
                                 + to_string(cnt);
                    alerts.emplace_back(
                            msg,
                            f->getUser(),
                            f->getIP(),
                            5,
                            f->getTimestamp(),
                            l->getTimestamp()
                    );
                }
                i++;
            }
        }
        return alerts;
    }
};

class IPBlacklistRule : public Rule {
    set<string> blacklist;
public:
    string name() const override { return "IPBlacklistRule"; }

    void configure(const string &line) override {
        auto pos = line.find(',');
        if (pos == string::npos) return;
        string rest = line.substr(pos + 1);

        string cur;
        for (size_t i = 0; i <= rest.size(); ++i) {
            if (i == rest.size() || rest[i] == ';') {
                if (!cur.empty()) {
                    size_t a = cur.find_first_not_of(" \t\r\n");
                    size_t b = cur.find_last_not_of(" \t\r\n");
                    blacklist.insert(a == string::npos ? string() : cur.substr(a, b - a + 1));
                }
                cur.clear();
            } else {
                cur.push_back(rest[i]);
            }
        }
    }

    vector<Alert> evaluate(const vector<SecurityLog> &logs) const override {
        vector<Alert> alerts;
        for (const auto &l: logs) {
            if (blacklist.count(l.getIP())) {
                alerts.emplace_back(
                        "Access from blacklisted IP",
                        l.getUser(),
                        l.getIP(),
                        max(4, l.getSeverity()),
                        l.getTimestamp(),
                        l.getTimestamp()
                );
            }
        }
        return alerts;
    }
};

// ===================== Logger =====================
class Logger {
public:
    void log(const string &msg) const {
        cout << ui::CYAN << "[INFO] " << msg << ui::RESET << "\n";
    }

    void log(const string &msg, int severity) const {
        string color = (severity >= 4) ? ui::RED : ui::YELLOW;
        cout << color << "[INFO-" << severity << "] " << msg << ui::RESET << "\n";
    }

    void log(const Alert &a) const {
        int sev = static_cast<int>(a);
        log("Alert with severity " + to_string(sev), sev);
    }
};

// ===================== IncidentReport =====================
class IncidentReport {
    Repository<Alert> alerts;
public:
    IncidentReport() = default;
    ~IncidentReport() = default;

    void add(const Alert &a) { alerts.add(a); }
    void clear() {
        IncidentReport tmp;
        *this = tmp;
    }
    const vector<Alert> &get() const { return alerts.getAll(); }

    void save(const string &path) const {
        ofstream ofs(path);
        if (!ofs) throw runtime_error("Cannot write report: " + path);
        ofs << "=== CyberSentinel Incident Report ===\n\n";
        for (const auto &a: alerts.getAll()) {
            ofs << a << "-----------------------------\n";
        }
    }

    size_t size() const { return alerts.size(); }
};

// ===================== LogAnalyzer =====================
class LogAnalyzer {
    vector<SecurityLog> logs;
    vector<unique_ptr<Rule>> rules;
public:
    void loadLogs(const string &path) {
        logs.clear();
        ifstream ifs(path);
        if (!ifs) throw runtime_error("Cannot open log file: " + path);

        string line;
        while (getline(ifs, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto cols = utils::splitCSV(line);
            if (cols.size() < 6) continue;

            time_t ts = utils::parseTimestamp(cols[0]);
            string user   = cols[1];
            string action = cols[2];
            string status = cols[3];
            string ip     = cols[4];
            int    sev    = stoi(cols[5]);

            logs.emplace_back(ts, user, action, status, ip, sev);
        }
        sort(logs.begin(), logs.end());
    }

    void loadRules(const string &path) {
        rules.clear();
        ifstream ifs(path);
        if (!ifs) throw runtime_error("Cannot open rules file: " + path);

        string line;
        while (getline(ifs, line)) {
            if (line.empty() || line[0] == '#') continue;

            if (line.rfind("THRESHOLD", 0) == 0) {
                auto r = make_unique<ThresholdRule>();
                r->configure(line);
                rules.push_back(std::move(r));
            } else if (line.rfind("BLACKLIST", 0) == 0) {
                auto r = make_unique<IPBlacklistRule>();
                r->configure(line);
                rules.push_back(std::move(r));
            }
        }
    }

    IncidentReport analyze() const {
        IncidentReport report;
        for (const auto &rp: rules) {
            auto alerts = rp->evaluate(logs);
            for (const auto &a: alerts) report.add(a);
        }
        return report;
    }

    const vector<SecurityLog> &getLogs() const { return logs; }
};

// ===================== Encryptor =====================
class Encryptor {
    int key{0};
public:
    explicit Encryptor(int k) : key(k) {}
    ~Encryptor() = default;

    string operator()(const string &text) const {
        string out = text;
        for (char &c: out) c = static_cast<char>(c ^ key);
        return out;
    }

    void encryptFile(const string &in, const string &out) const {
        ifstream ifs(in, ios::binary);
        if (!ifs) throw runtime_error("Cannot open input: " + in);
        ofstream ofs(out, ios::binary);
        if (!ofs) throw runtime_error("Cannot open output: " + out);
        char ch;
        while (ifs.get(ch)) ofs.put(static_cast<char>(ch ^ key));
    }

    void decryptFile(const string &in, const string &out) const {
        encryptFile(in, out); // XOR symmetric
    }
};

// ===================== Behavior Analysis & Charts =====================
struct UserProfile {
    string normalIP = "";
    int morning = 0, afternoon = 0, night = 0;
    int success = 0, fail = 0;
};

string getTimeSlot(time_t t) {
    int hour = localtime(&t)->tm_hour;
    if (hour >= 5 && hour < 12) return "MORNING";
    if (hour >= 12 && hour < 18) return "AFTERNOON";
    return "NIGHT";
}

void behaviorAnalysis(const vector<SecurityLog>& logs) {
    if (logs.empty()) {
        cout << ui::YELLOW << "No logs available for behavior analysis.\n" << ui::RESET;
        return;
    }

    map<string, UserProfile> profile;

    for (const auto &l : logs) {
        auto &p = profile[l.getUser()];
        string slot = getTimeSlot(l.getTimestamp());
        if (slot == "MORNING") p.morning++;
        else if (slot == "AFTERNOON") p.afternoon++;
        else p.night++;

        if (p.normalIP.empty()) p.normalIP = l.getIP();

        if (l.getStatus() == "FAILED") p.fail++;
        else p.success++;
    }

    cout << ui::BOLD << "\n======== BEHAVIOR ANALYSIS ========\n" << ui::RESET;

    for (const auto &kv : profile) {
        const string &user = kv.first;
        const UserProfile &p = kv.second;

        string normalSlot;
        if (p.morning >= p.afternoon && p.morning >= p.night) normalSlot = "MORNING";
        else if (p.afternoon >= p.night) normalSlot = "AFTERNOON";
        else normalSlot = "NIGHT";

        float failRate = (p.fail + p.success == 0)
                         ? 0.0f : (float)p.fail / (p.fail + p.success);

        cout << "\nUser: " << ui::BOLD << user << ui::RESET << "\n";
        cout << "  Normal login time window: " << normalSlot << "\n";
        cout << "  Normal IP: " << p.normalIP << "\n";
        cout << "  Success logins: " << p.success
             << ", Failed logins: " << p.fail
             << " (failure rate: " << failRate * 100 << "%)\n";

        if (failRate > 0.5f)
            cout << ui::RED << "  -> High failure rate: user may be under attack or misusing password.\n" << ui::RESET;
        else if (failRate > 0.2f)
            cout << ui::YELLOW << "  -> Moderate failure rate: monitor this account.\n" << ui::RESET;
        else
            cout << ui::GREEN << "  -> Normal behavior.\n" << ui::RESET;
    }

    cout << "\n(Behavior analysis uses historical logs to understand usual patterns and detect risky users.)\n";
}

void asciiBarChart(const map<string,int> &data, const string &title) {
    cout << ui::BOLD << "\n===== " << title << " =====\n" << ui::RESET;
    if (data.empty()) {
        cout << ui::YELLOW << "No data to display.\n" << ui::RESET;
        return;
    }
    for (auto &[user, count] : data) {
        cout << user << "\t";
        for (int i = 0; i < count; i++)
            cout << "█";
        cout << "  " << count << "\n";
    }
}

// ===================== Threat Summary & Recommendations =====================
void threatSummaryAndRecommendations(const vector<SecurityLog> &logs) {
    if (logs.empty()) {
        cout << ui::YELLOW << "No logs available. Create system logs first.\n" << ui::RESET;
        return;
    }

    int totalLogs = (int)logs.size();
    map<string,int> failedByUser;
    map<string,int> failedByIP;
    int highSeverityOps = 0;

    for (const auto &l : logs) {
        if (l.getAction() == "LOGIN" && l.getStatus() == "FAILED") {
            failedByUser[l.getUser()]++;
            failedByIP[l.getIP()]++;
        }
        if (l.getSeverity() >= 4) highSeverityOps++;
    }

    cout << ui::BOLD << "\n============== THREAT SUMMARY ==============\n" << ui::RESET;
    cout << "Total log entries: " << totalLogs << "\n";
    cout << "High severity operations: " << highSeverityOps << "\n\n";

    bool bruteForceDetected = false;
    string bruteUser;
    for (auto &p : failedByUser) {
        if (p.second >= 5) {
            bruteForceDetected = true;
            bruteUser = p.first;
            break;
        }
    }

    if (bruteForceDetected) {
        cout << ui::RED << "[!] Brute-force login pattern suspected for user: "
             << bruteUser << " (>= 5 failed logins)\n" << ui::RESET;
    } else {
        cout << ui::GREEN << "[OK] No strong brute-force pattern detected by user.\n" << ui::RESET;
    }

    int riskyIPs = 0;
    for (auto &p : failedByIP) {
        if (p.second >= 5) riskyIPs++;
    }
    if (riskyIPs > 0) {
        cout << ui::RED << "[!] Some IPs show repeated failed access attempts.\n" << ui::RESET;
    } else {
        cout << ui::GREEN << "[OK] No IP with extremely high failed attempts.\n" << ui::RESET;
    }

    int riskScore = 0;
    riskScore += bruteForceDetected ? 40 : 0;
    riskScore += min(highSeverityOps * 2, 30);
    riskScore += min((int)failedByIP.size() * 3, 30);

    cout << "\nOverall Risk Score (0–100): ";
    if (riskScore >= 70) {
        cout << ui::RED << riskScore << " [HIGH]\n" << ui::RESET;
    } else if (riskScore >= 40) {
        cout << ui::YELLOW << riskScore << " [MEDIUM]\n" << ui::RESET;
    } else {
        cout << ui::GREEN << riskScore << " [LOW]\n" << ui::RESET;
    }

    cout << ui::BOLD << "\nRecommended Actions:\n" << ui::RESET;
    if (riskScore >= 70) {
        cout << " - Immediately review accounts with many failures.\n";
        cout << " - Block suspicious IPs at firewall level.\n";
        cout << " - Enforce strong passwords and enable 2FA.\n";
        cout << " - Monitor logs in near real-time.\n";
    } else if (riskScore >= 40) {
        cout << " - Monitor users with repeated failures.\n";
        cout << " - Review recent high-severity operations.\n";
        cout << " - Educate users about safe password practices.\n";
    } else {
        cout << " - Maintain current security posture.\n";
        cout << " - Periodically review logs and update rules.\n";
    }

    cout << "\nSimple Event Timeline (last few entries):\n";
    int show = min(5, (int)logs.size());
    for (int i = (int)logs.size() - show; i < (int)logs.size(); ++i) {
        const auto &l = logs[i];
        cout << " - " << utils::formatTimestamp(l.getTimestamp())
             << " | " << l.getUser() << "@" << l.getIP()
             << " | " << l.getAction() << "/" << l.getStatus()
             << " | sev=" << l.getSeverity() << "\n";
    }
    cout << "\n(This summary helps understand how risky the current activity is and what steps to take.)\n";
}

// ===================== Role & Accounts =====================
enum class Role { ADMIN, ANALYST, AUDITOR };

string roleToString(Role r) {
    switch (r) {
        case Role::ADMIN:   return "ADMIN";
        case Role::ANALYST: return "ANALYST";
        case Role::AUDITOR: return "AUDITOR";
    }
    return "ADMIN";
}

string roleToLabel(Role r) {
    switch (r) {
        case Role::ADMIN:   return "Security Admin";
        case Role::ANALYST: return "Security Analyst";
        case Role::AUDITOR: return "Security Auditor";
    }
    return "Security Admin";
}

struct Account {
    Role role;
    string username;
    string password;
};

void ensureKeyFile() {
    ifstream k("encrypted.key");
    if (!k.good()) {
        ofstream o("encrypted.key");
        o << 37 << "\n";      // default XOR key
    }
}

void ensureAccountsFile() {
    ifstream in("accounts.txt");
    if (in.good()) return;
    ofstream out("accounts.txt");
    out << "ADMIN admin admin123\n";
    out << "ANALYST analyst analyst123\n";
    out << "AUDITOR auditor auditor123\n";
}

void ensureSampleFiles() {
    {
        ifstream l("system_logs.txt");
        if (!l.good()) {
            ofstream o("system_logs.txt");
            o << "# timestamp, user, action, status, ip, severity\n"
              << "2025-11-07 09:41:21, root, LOGIN, FAILED, 192.168.1.10, 3\n"
              << "2025-11-07 09:41:25, root, LOGIN, FAILED, 192.168.1.10, 3\n"
              << "2025-11-07 09:41:29, root, LOGIN, FAILED, 192.168.1.10, 3\n"
              << "2025-11-07 09:41:35, root, LOGIN, FAILED, 192.168.1.10, 3\n"
              << "2025-11-07 09:41:40, root, LOGIN, FAILED, 192.168.1.10, 3\n"
              << "2025-11-07 10:15:10, alice, DOWNLOAD, SUCCESS, 10.0.0.5, 1\n"
              << "2025-11-07 10:18:00, bob, LOGIN, SUCCESS, 172.16.0.2, 1\n"
              << "2025-11-07 10:19:02, charlie, DELETE, SUCCESS, 203.0.113.7, 4\n";
        }
    }
    {
        ifstream r("rules.txt");
        if (!r.good()) {
            ofstream o("rules.txt");
            o << "# THRESHOLD,action,status,windowSeconds,threshold\n"
              << "THRESHOLD,LOGIN,FAILED,120,5\n"
              << "# BLACKLIST,ip1;ip2;...\n"
              << "BLACKLIST,203.0.113.7;198.51.100.25\n";
        }
    }
}

vector<Account> loadAccounts() {
    vector<Account> accounts;
    ifstream in("accounts.txt");
    string r, u, p;
    while (in >> r >> u >> p) {
        Role role;
        if (r == "ADMIN") role = Role::ADMIN;
        else if (r == "ANALYST") role = Role::ANALYST;
        else if (r == "AUDITOR") role = Role::AUDITOR;
        else continue;
        accounts.push_back({role, u, p});
    }
    return accounts;
}

void saveAccounts(const vector<Account> &accounts) {
    ofstream out("accounts.txt");
    for (const auto &acc : accounts) {
        out << roleToString(acc.role) << " "
            << acc.username << " "
            << acc.password << "\n";
    }
}

int findAccountIndex(const vector<Account> &accounts, Role role) {
    for (size_t i = 0; i < accounts.size(); ++i) {
        if (accounts[i].role == role) return (int)i;
    }
    return -1;
}

// ===================== SETTINGS (change passwords) =====================
int readIntLine() {
    string s;
    getline(cin, s);
    if (s.empty()) return -1;
    try { return stoi(s); }
    catch (...) { return -1; }
}

void runSettingsMenu(vector<Account> &accounts) {
    for (;;) {
        ui::printHeader();
        cout << ui::MAGENTA << ui::BOLD << "================ SETTINGS ================\n" << ui::RESET;
        cout << ui::CYAN << "Some options may be restricted based on your role.\n\n" << ui::RESET;
        cout << ui::YELLOW << "1) " << ui::GREEN << "Change Admin password\n";
        cout << ui::YELLOW << "2) " << ui::GREEN << "Change Analyst password\n";
        cout << ui::YELLOW << "3) " << ui::GREEN << "Change Auditor password\n";
        cout << ui::YELLOW << "4) " << ui::RED   << "Back\n" << ui::RESET;
        cout << ui::BOLD << "Choice: " << ui::RESET;
        int choice = readIntLine();

        if (choice == 4) break;

        Role targetRole;
        if (choice == 1) targetRole = Role::ADMIN;
        else if (choice == 2) targetRole = Role::ANALYST;
        else if (choice == 3) targetRole = Role::AUDITOR;
        else {
            cout << ui::RED << "Invalid choice.\n" << ui::RESET;
            ui::pause();
            continue;
        }

        int idx = findAccountIndex(accounts, targetRole);
        if (idx < 0) {
            cout << ui::RED << "Account not found in accounts.txt\n" << ui::RESET;
            ui::pause();
            continue;
        }

        cout << ui::CYAN << "Enter current password for [" << roleToLabel(targetRole) << "]: " << ui::RESET;
        string oldPass;
        getline(cin, oldPass);

        if (oldPass != accounts[idx].password) {
            cout << ui::RED << "Incorrect current password.\n" << ui::RESET;
            ui::pause();
            continue;
        }

        cout << ui::CYAN << "Enter new password: " << ui::RESET;
        string newPass;
        getline(cin, newPass);
        cout << ui::CYAN << "Confirm new password: " << ui::RESET;
        string confirm;
        getline(cin, confirm);

        if (newPass != confirm) {
            cout << ui::RED << "Passwords do not match.\n" << ui::RESET;
            ui::pause();
            continue;
        }

        accounts[idx].password = newPass;
        saveAccounts(accounts);
        cout << ui::GREEN << "Password updated successfully.\n" << ui::RESET;
        ui::pause();
    }
}

// ===================== Admin / Session =====================
class AdminBase : public Timestamped {
protected:
    string roleLabel{"Unknown"};
public:
    virtual ~AdminBase() = default;
    virtual string getRoleLabel() const { return roleLabel; }
};

class Admin : public AdminBase {
    Role currentRole;
    string currentUsername;
    Logger logger;

    int readChoiceInt() const {
        return readIntLine();
    }

    void sectionLogManagement(LogAnalyzer &la);
    void sectionSecurityAnalysis(LogAnalyzer &la);
    void sectionReportingEncryption(LogAnalyzer &la);
    void sectionRulesConfig(LogAnalyzer &la);
    void sectionUtilitiesHelp(LogAnalyzer &la);

public:
    Admin(Role r) {
        currentRole = r;
        roleLabel = roleToLabel(r);
    }

    Role getRoleType() const { return currentRole; }
    const string &getUsername() const { return currentUsername; }

    bool login(const vector<Account> &accounts) {
        string u, p;
        cout << ui::BOLD << ui::CYAN << "=== Login: " << roleLabel << " ===\n" << ui::RESET;
        for (int attempts = 0; attempts < 3; ++attempts) {
            cout << ui::YELLOW << "Username: " << ui::RESET;
            getline(cin, u);
            cout << ui::YELLOW << "Password: " << ui::RESET;
            getline(cin, p);

            bool ok = false;
            for (const auto &acc : accounts) {
                if (acc.role == currentRole &&
                    acc.username == u &&
                    acc.password == p) {
                    ok = true;
                    break;
                }
            }

            if (ok) {
                cout << ui::GREEN << "Login successful.\n" << ui::RESET;
                currentUsername = u;
                return true;
            }
            cout << ui::RED << "Invalid credentials. Try again.\n" << ui::RESET;
        }
        cout << ui::RED << "Too many failed login attempts.\n" << ui::RESET;
        return false;
    }

    void showResources() const {
        cout << ui::MAGENTA << "\nUseful Security / IDS Resources:\n" << ui::RESET;
        cout << ui::CYAN << " - OWASP:          " << ui::GREEN << "https://owasp.org/\n";
        cout << ui::CYAN << " - MITRE ATT&CK:   " << ui::GREEN << "https://attack.mitre.org/\n";
        cout << ui::CYAN << " - Snort IDS:      " << ui::GREEN << "https://www.snort.org/\n";
        cout << ui::CYAN << " - Suricata IDS:   " << ui::GREEN << "https://suricata.io/\n\n" << ui::RESET;
    }

    void showLogsPreview(const LogAnalyzer &la) const {
        cout << ui::BLUE << "\nSample logs (first 3):\n" << ui::RESET;
        const auto &logs = la.getLogs();
        for (size_t i = 0; i < logs.size() && i < 3; ++i) {
            logs[i].printPretty();
        }
    }

    void menu(LogAnalyzer &la) {
        for (;;) {
            ui::printHeader();
            cout << ui::BOLD << ui::GREEN << "Logged in as: " << ui::YELLOW << currentUsername
                 << ui::RESET << "  (" << ui::CYAN << roleLabel << ui::RESET << ")\n";
            cout << ui::CYAN << "Some options may be restricted based on your role.\n\n" << ui::RESET;

            struct SectionItem { int id; string label; };
            vector<SectionItem> sections;

            // Role-based allowed sections:
            if (currentRole == Role::ADMIN || currentRole == Role::ANALYST)
                sections.push_back({1, "LOG MANAGEMENT"});
            if (currentRole == Role::ADMIN || currentRole == Role::ANALYST)
                sections.push_back({2, "SECURITY ANALYSIS & VISUALS"});
            if (currentRole == Role::ADMIN || currentRole == Role::AUDITOR)
                sections.push_back({3, "REPORTING & ENCRYPTION"});
            if (currentRole == Role::ADMIN)
                sections.push_back({4, "RULES & CONFIGURATION"});
            if (currentRole == Role::ADMIN)
                sections.push_back({5, "UTILITIES & HELP"});

            cout << ui::GREEN << ui::BOLD << "=== MAIN MENU ===\n" << ui::RESET;
            for (size_t i = 0; i < sections.size(); ++i) {
                cout << ui::YELLOW << (i + 1) << ") " << ui::CYAN << sections[i].label << ui::RESET << "\n";
            }
            cout << ui::YELLOW << (sections.size() + 1) << ") " << ui::RED << "Logout\n" << ui::RESET;
            cout << ui::BOLD << "Choice: " << ui::RESET;

            int choice = readChoiceInt();
            if (choice == (int)sections.size() + 1) {
                logger.log("Logging out...");
                break;
            }
            if (choice <= 0 || choice > (int)sections.size()) {
                cout << ui::RED << "Invalid choice.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            int sectionId = sections[choice - 1].id;
            switch (sectionId) {
                case 1: sectionLogManagement(la);      break;
                case 2: sectionSecurityAnalysis(la);   break;
                case 3: sectionReportingEncryption(la);break;
                case 4: sectionRulesConfig(la);        break;
                case 5: sectionUtilitiesHelp(la);      break;
            }
        }
    }
};

// ========== SECTION 1: LOG MANAGEMENT ==========
void Admin::sectionLogManagement(LogAnalyzer &la) {
    for (;;) {
        ui::printHeader();
        cout << ui::BLUE << ui::BOLD << "=== 1. LOG MANAGEMENT ===\n" << ui::RESET;
        cout << ui::CYAN << "1) " << ui::GREEN << "Analyze logs & generate incident report\n";
        cout << ui::CYAN << "2) " << ui::GREEN << "Take user logs & analyze (LOGIN attempts)\n";
        cout << ui::CYAN << "3) " << ui::GREEN << "Search logs\n";
        cout << ui::CYAN << "4) " << ui::GREEN << "Create system_logs.txt (user input)\n";
        cout << ui::CYAN << "5) " << ui::RED   << "Back\n" << ui::RESET;
        cout << ui::BOLD << "Choice: " << ui::RESET;
        int c = readChoiceInt();
        if (c == 5) break;

        if (c == 1) {
            try {
                auto start = chrono::steady_clock::now();
                auto report = la.analyze();
                report.save("incident_report.txt");

                cout << ui::YELLOW << "Do you want to add your own notes to the incident report? (yes/no): " << ui::RESET;
                string addNote;
                getline(cin, addNote);
                if (addNote == "yes") {
                    cout << ui::CYAN << "Enter your notes (type END to finish):\n" << ui::RESET;
                    ofstream noteFile("incident_report.txt", ios::app);
                    noteFile << "\n--- Analyst Notes ---\n";
                    while (true) {
                        string line;
                        getline(cin, line);
                        if (line == "END") break;
                        noteFile << line << "\n";
                    }
                    noteFile.close();
                    cout << ui::GREEN << "Notes added successfully.\n" << ui::RESET;
                }

                ofstream passFile("report_pass.txt");
                cout << ui::CYAN << "Set a password to protect the report: " << ui::RESET;
                string setPass;
                getline(cin, setPass);
                passFile << setPass;
                passFile.close();
                cout << ui::GREEN << "Password saved. Report is now protected.\n" << ui::RESET;

                ofstream a("alerts.txt");
                for (const auto &al: report.get()) a << al << "\n";
                auto end = chrono::steady_clock::now();
                auto ms = chrono::duration_cast<chrono::milliseconds>(end - start).count();
                logger.log("Incident report saved: incident_report.txt", 3);
                cout << ui::YELLOW << "Analysis time: " << ms << " ms\n" << ui::RESET;
            } catch (const exception &e) {
                cout << ui::RED << e.what() << ui::RESET << "\n";
            }
            ui::pause();
        }
        else if (c == 2) {
            cout << ui::YELLOW << "\n=== User Log Input Mode ===\n" << ui::RESET;
            cout << ui::CYAN << "How many log entries do you want to enter?: " << ui::RESET;
            int n = readChoiceInt();
            if (n <= 0) {
                cout << ui::RED << "Invalid count.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            ofstream out("user_logs.txt");
            if (!out) {
                cout << ui::RED << "Cannot create user_logs.txt file!\n" << ui::RESET;
                ui::pause();
                continue;
            }

            cout << ui::CYAN << "\nEntry format: USER ACTION STATUS\n";
            cout << "Example:  root LOGIN FAILED\n\n" << ui::RESET;

            for (int i = 0; i < n; i++) {
                string user, action, status;
                cout << ui::YELLOW << "Entry " << (i + 1) << ": " << ui::RESET;
                cin >> user >> action >> status;
                out << user << " " << action << " " << status << "\n";
            }
            cin.ignore();
            out.close();

            cout << ui::GREEN << "\nLog entries saved to user_logs.txt.\n" << ui::RESET;

            ifstream in("user_logs.txt");
            if (!in) {
                cout << ui::RED << "Cannot read user_logs.txt file!\n" << ui::RESET;
                ui::pause();
                continue;
            }

            string user, act, status;
            int totalLoginAttempts = 0;
            int failedLoginCount   = 0;

            while (in >> user >> act >> status) {
                if (act == "LOGIN") {
                    totalLoginAttempts++;
                    if (status == "FAILED") failedLoginCount++;
                }
            }
            in.close();

            cout << ui::BOLD << "\n======= USER LOGIN ANALYSIS =======\n" << ui::RESET;
            cout << ui::CYAN << "Total login attempts: " << ui::YELLOW << totalLoginAttempts << "\n";
            cout << ui::CYAN << "Total failed logins: " << ui::YELLOW << failedLoginCount << "\n" << ui::RESET;

            if (failedLoginCount >= 3)
                cout << ui::RED << "WARNING: Multiple FAILED login attempts detected!\n" << ui::RESET;
            else
                cout << ui::GREEN << "Login activity is normal.\n" << ui::RESET;

            ui::pause();
        }
        else if (c == 3) {
            const auto &logs = la.getLogs();
            if (logs.empty()) {
                cout << ui::RED << "No logs loaded. Use option 4 to create system logs.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            cout << ui::CYAN << "Search by:\n"
                    "1) Username\n"
                    "2) IP address\n"
                    "3) Action\n" << ui::RESET;
            cout << ui::BOLD << "Choice: " << ui::RESET;
            int sc = readChoiceInt();

            string query;
            if (sc == 1) {
                cout << ui::CYAN << "Enter username: " << ui::RESET;
                getline(cin, query);
            } else if (sc == 2) {
                cout << ui::CYAN << "Enter IP address: " << ui::RESET;
                getline(cin, query);
            } else if (sc == 3) {
                cout << ui::CYAN << "Enter action (e.g., LOGIN, DELETE): " << ui::RESET;
                getline(cin, query);
            } else {
                cout << ui::RED << "Invalid search choice.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            cout << ui::BLUE << "\nSearch results:\n" << ui::RESET;
            int count = 0;
            for (const auto &l : logs) {
                bool match = false;
                if (sc == 1 && l.getUser() == query) match = true;
                if (sc == 2 && l.getIP() == query) match = true;
                if (sc == 3 && l.getAction() == query) match = true;
                if (match) {
                    l.printPretty();
                    count++;
                }
            }
            if (count == 0)
                cout << ui::YELLOW << "No matching logs found.\n" << ui::RESET;
            else
                cout << ui::GREEN << "Total matches: " << count << "\n" << ui::RESET;

            ui::pause();
        }
        else if (c == 4) {
            cout << ui::YELLOW << "\n=== System Log Creator ===\n" << ui::RESET;

            cout << ui::CYAN << "Do you want to overwrite existing system_logs.txt (if any)? (yes/no): " << ui::RESET;
            string ow;
            getline(cin, ow);
            ios::openmode mode = ios::out;
            if (ow != "yes") mode |= ios::app;

            ofstream out("system_logs.txt", mode);
            if (!out) {
                cout << ui::RED << "Cannot open system_logs.txt for writing.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            while (true) {
                cout << ui::CYAN << "\nCreate new log entry? (yes/no): " << ui::RESET;
                string ans;
                getline(cin, ans);
                if (ans != "yes") break;

                string ts, user, ip;
                cout << ui::CYAN << "Timestamp (YYYY-MM-DD HH:MM:SS): " << ui::RESET;
                getline(cin, ts);
                cout << ui::CYAN << "Username: " << ui::RESET;
                getline(cin, user);
                cout << ui::CYAN << "IP address: " << ui::RESET;
                getline(cin, ip);

                cout << ui::CYAN << "\nChoose action:\n"
                        "1) LOGIN\n"
                        "2) DELETE\n"
                        "3) DOWNLOAD\n"
                        "4) UPLOAD\n" << ui::RESET;
                cout << ui::BOLD << "Choice: " << ui::RESET;
                int ac = readChoiceInt();
                string action = "LOGIN";
                if (ac == 2) action = "DELETE";
                else if (ac == 3) action = "DOWNLOAD";
                else if (ac == 4) action = "UPLOAD";

                cout << ui::CYAN << "\nChoose status:\n"
                        "1) SUCCESS\n"
                        "2) FAILED\n" << ui::RESET;
                cout << ui::BOLD << "Choice: " << ui::RESET;
                int st = readChoiceInt();
                string status = (st == 2) ? "FAILED" : "SUCCESS";

                cout << ui::CYAN << "\nChoose severity:\n"
                        "1) Low\n"
                        "2) Medium\n"
                        "3) High\n"
                        "4) Critical\n" << ui::RESET;
                cout << ui::BOLD << "Choice: " << ui::RESET;
                int sv = readChoiceInt();
                if (sv < 1 || sv > 4) sv = 1;

                out << ts << ", " << user << ", " << action << ", "
                    << status << ", " << ip << ", " << sv << "\n";

                cout << ui::GREEN << "Log entry added.\n" << ui::RESET;
            }
            out.close();

            try {
                la.loadLogs("system_logs.txt");
                cout << ui::GREEN << "system_logs.txt created and loaded into analyzer.\n" << ui::RESET;
            } catch (const exception &e) {
                cout << ui::RED << "Error loading logs: " << e.what() << ui::RESET << "\n";
            }
            ui::pause();
        }
        else {
            cout << ui::RED << "Invalid choice.\n" << ui::RESET;
            ui::pause();
        }
    }
}

// ========== SECTION 2: SECURITY ANALYSIS & VISUALS ==========
void Admin::sectionSecurityAnalysis(LogAnalyzer &la) {
    for (;;) {
        ui::printHeader();
        cout << ui::CYAN << ui::BOLD << "=== 2. SECURITY ANALYSIS & VISUALS ===\n" << ui::RESET;
        cout << ui::CYAN << "1) " << ui::GREEN << "Behavior analysis (user profiling)\n";
        cout << ui::CYAN << "2) " << ui::GREEN << "Show failed login bar chart\n";
        cout << ui::CYAN << "3) " << ui::GREEN << "Threat summary & recommendations\n";
        cout << ui::CYAN << "4) " << ui::GREEN << "Show system statistics\n";
        cout << ui::CYAN << "5) " << ui::RED   << "Back\n" << ui::RESET;
        cout << ui::BOLD << "Choice: " << ui::RESET;
        int c = readChoiceInt();
        if (c == 5) break;

        const auto &logs = la.getLogs();
        if (logs.empty()) {
            cout << ui::RED << "No logs loaded. Create or load system logs first.\n" << ui::RESET;
            ui::pause();
            continue;
        }

        if (c == 1) {
            behaviorAnalysis(logs);
            ui::pause();
        } else if (c == 2) {
            map<string,int> chart;
            for (auto &l : logs) {
                if (l.getAction() == "LOGIN" && l.getStatus() == "FAILED")
                    chart[l.getUser()]++;
            }
            asciiBarChart(chart, "FAILED LOGIN FREQUENCY (by user)");
            ui::pause();
        } else if (c == 3) {
            threatSummaryAndRecommendations(logs);
            ui::pause();
        } else if (c == 4) {
            size_t totalLogs = logs.size();
            int failedLogins = 0;
            int successfulLogins = 0;
            set<string> users, ips;
            map<string,int> userFailCount;

            for (const auto &l : logs) {
                users.insert(l.getUser());
                ips.insert(l.getIP());
                if (l.getAction() == "LOGIN") {
                    if (l.getStatus() == "FAILED") {
                        failedLogins++;
                        userFailCount[l.getUser()]++;
                    } else {
                        successfulLogins++;
                    }
                }
            }

            string topUser = "N/A";
            int topFails = 0;
            for (auto &p : userFailCount) {
                if (p.second > topFails) {
                    topFails = p.second;
                    topUser = p.first;
                }
            }

            cout << ui::BOLD << "\n=== System Statistics ===\n" << ui::RESET;
            cout << ui::CYAN << "Total logs loaded      : " << ui::YELLOW << totalLogs << "\n";
            cout << ui::CYAN << "Unique users           : " << ui::YELLOW << users.size() << "\n";
            cout << ui::CYAN << "Unique IPs             : " << ui::YELLOW << ips.size() << "\n";
            cout << ui::CYAN << "Total LOGIN success    : " << ui::YELLOW << successfulLogins << "\n";
            cout << ui::CYAN << "Total LOGIN failed     : " << ui::YELLOW << failedLogins << "\n";
            cout << ui::CYAN << "Most targeted user     : " << ui::YELLOW << topUser
                 << " (failed logins: " << topFails << ")\n" << ui::RESET;
            ui::pause();
        } else {
            cout << ui::RED << "Invalid choice.\n" << ui::RESET;
            ui::pause();
        }
    }
}

// ========== SECTION 3: REPORTING & ENCRYPTION ==========
void Admin::sectionReportingEncryption(LogAnalyzer & /*la*/) {
    for (;;) {
        ui::printHeader();
        cout << ui::MAGENTA << ui::BOLD << "=== 3. REPORTING & ENCRYPTION ===\n" << ui::RESET;

        // Role-based sub-options (Auditor is view-only)
        struct Item { int id; string label; };
        vector<Item> items;

        if (currentRole == Role::ADMIN) {
            items.push_back({1, "View last report (password protected)"});
            items.push_back({2, "Add quick incident notes (templates)"});
            items.push_back({3, "Export report to another file"});
            items.push_back({4, "Encrypt report"});
            items.push_back({5, "Decrypt report"});
        } else if (currentRole == Role::AUDITOR) {
            items.push_back({1, "View last report (password protected)"});
            items.push_back({3, "Export report to another file"});
        }

        for (size_t i = 0; i < items.size(); ++i) {
            cout << ui::YELLOW << (i + 1) << ") " << ui::CYAN << items[i].label << ui::RESET << "\n";
        }
        cout << ui::YELLOW << (items.size() + 1) << ") " << ui::RED << "Back\n" << ui::RESET;
        cout << ui::BOLD << "Choice: " << ui::RESET;
        int c = readChoiceInt();
        if (c == (int)items.size() + 1) break;
        if (c <= 0 || c > (int)items.size()) {
            cout << ui::RED << "Invalid choice.\n" << ui::RESET;
            ui::pause();
            continue;
        }

        int id = items[c - 1].id;

        if (id == 1) {
            ifstream pf("report_pass.txt");
            if (!pf) {
                cout << ui::RED << "No password set. Cannot open report.\n" << ui::RESET;
                ui::pause();
                continue;
            }
            string savedPass;
            getline(pf, savedPass);
            pf.close();

            cout << ui::CYAN << "Enter report password: " << ui::RESET;
            string userPass;
            getline(cin, userPass);

            if (userPass != savedPass) {
                cout << ui::RED << "Incorrect password! Access denied.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            ifstream ifs("incident_report.txt");
            if (!ifs) {
                cout << ui::RED << "No report found.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            cout << ui::GREEN << "Access granted.\n\n" << ui::RESET;
            cout << ui::BOLD << ifs.rdbuf() << ui::RESET;
            ui::pause();
        }
        else if (id == 2 && currentRole == Role::ADMIN) {
            ifstream check("incident_report.txt");
            if (!check) {
                cout << ui::RED << "No incident_report.txt found. Run analysis first.\n" << ui::RESET;
                ui::pause();
                continue;
            }
            check.close();

            cout << ui::CYAN
                 << "Choose note template:\n"
                    "1) Brute force attack note\n"
                    "2) Blacklisted IP note\n"
                    "3) Suspicious user behaviour\n" << ui::RESET;
            cout << ui::BOLD << "Choice: " << ui::RESET;
            int nc = readChoiceInt();

            string note;
            if (nc == 1) {
                note =
                    "This incident appears to be a brute-force login attempt on a privileged account.\n"
                    "Multiple failed login attempts were detected in a short time window.\n";
            } else if (nc == 2) {
                note =
                    "Activity was detected from a blacklisted IP address.\n"
                    "This source should be blocked and investigated further.\n";
            } else if (nc == 3) {
                note =
                    "User behaviour appears abnormal compared to usual login patterns.\n"
                    "Further monitoring and verification of user identity is recommended.\n";
            } else {
                cout << ui::RED << "Invalid template choice.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            ofstream nf("incident_report.txt", ios::app);
            nf << "\n--- Quick Incident Note ---\n" << note;
            cout << ui::GREEN << "Quick note added to report.\n" << ui::RESET;
            ui::pause();
        }
        else if (id == 3) {
            ifstream src("incident_report.txt");
            if (!src) {
                cout << ui::RED << "No report to export.\n" << ui::RESET;
                ui::pause();
                continue;
            }
            cout << ui::CYAN << "Enter export file name (e.g., report_copy.txt): " << ui::RESET;
            string fname;
            getline(cin, fname);
            if (fname.empty()) fname = "incident_report_copy.txt";

            ofstream dst(fname);
            if (!dst) {
                cout << ui::RED << "Cannot write to " << fname << "\n" << ui::RESET;
                ui::pause();
                continue;
            }
            dst << src.rdbuf();
            cout << ui::GREEN << "Report exported to " << fname << "\n" << ui::RESET;
            ui::pause();
        }
        else if (id == 4 && currentRole == Role::ADMIN) {
            ifstream kf("encrypted.key");
            int key = 0;
            if (!(kf >> key)) {
                logger.log("Key file missing or invalid", 4);
                ui::pause();
                continue;
            }
            Encryptor enc(key);
            try {
                enc.encryptFile("incident_report.txt", "incident_report.enc");
                logger.log("Encrypted -> incident_report.enc", 4);
            } catch (const exception &e) {
                cout << ui::RED << e.what() << ui::RESET << "\n";
            }
            ui::pause();
        }
        else if (id == 5 && currentRole == Role::ADMIN) {
            ifstream kf("encrypted.key");
            int key = 0;
            if (!(kf >> key)) {
                logger.log("Key file missing or invalid", 4);
                ui::pause();
                continue;
            }
            Encryptor enc(key);
            try {
                enc.decryptFile("incident_report.enc", "incident_report.txt");
                logger.log("Decrypted -> incident_report.txt", 3);
            } catch (const exception &e) {
                cout << ui::RED << e.what() << ui::RESET << "\n";
            }
            ui::pause();
        }
        else {
            cout << ui::RED << "Option not available for your role.\n" << ui::RESET;
            ui::pause();
        }
    }
}

// ========== SECTION 4: RULES & CONFIGURATION ==========
void Admin::sectionRulesConfig(LogAnalyzer &la) {
    for (;;) {
        ui::printHeader();
        cout << ui::YELLOW << ui::BOLD << "=== 4. RULES & CONFIGURATION ===\n" << ui::RESET;
        cout << ui::CYAN << "1) " << ui::GREEN << "Create rules.txt (rule builder)\n";
        cout << ui::CYAN << "2) " << ui::GREEN << "Edit existing rules.txt\n";
        cout << ui::CYAN << "3) " << ui::GREEN << "Change report password\n";
        cout << ui::CYAN << "4) " << ui::GREEN << "Delete previous report files\n";
        cout << ui::CYAN << "5) " << ui::RED   << "Back\n" << ui::RESET;
        cout << ui::BOLD << "Choice: " << ui::RESET;
        int c = readChoiceInt();
        if (c == 5) break;

        if (c == 1) {
            cout << ui::YELLOW << "\n=== Rule Builder ===\n" << ui::RESET;
            ofstream out("rules.txt");
            if (!out) {
                cout << ui::RED << "Cannot open rules.txt for writing.\n" << ui::RESET;
                ui::pause();
                continue;
            }

            while (true) {
                cout << ui::CYAN << "\nAdd rule:\n"
                        "1) Threshold rule\n"
                        "2) Blacklist rule\n"
                        "3) Done\n" << ui::RESET;
                cout << ui::BOLD << "Choice: " << ui::RESET;
                int rc = readChoiceInt();
                if (rc == 3) break;

                if (rc == 1) {
                    cout << ui::CYAN << "Enter action (e.g., LOGIN, DELETE): " << ui::RESET;
                    string action;
                    getline(cin, action);

                    cout << ui::CYAN << "Choose status:\n"
                            "1) SUCCESS\n"
                            "2) FAILED\n" << ui::RESET;
                    cout << ui::BOLD << "Choice: " << ui::RESET;
                    int st = readChoiceInt();
                    string status = (st == 2) ? "FAILED" : "SUCCESS";

                    cout << ui::CYAN << "Enter time window in seconds (e.g., 120): " << ui::RESET;
                    int wnd = readChoiceInt();
                    if (wnd <= 0) wnd = 120;

                    cout << ui::CYAN << "Enter threshold count (e.g., 5): " << ui::RESET;
                    int thr = readChoiceInt();
                    if (thr <= 0) thr = 5;

                    out << "THRESHOLD," << action << "," << status << ","
                        << wnd << "," << thr << "\n";
                    cout << ui::GREEN << "Threshold rule added.\n" << ui::RESET;

                } else if (rc == 2) {
                    cout << ui::CYAN << "How many blacklisted IPs do you want to add?: " << ui::RESET;
                    int n = readChoiceInt();
                    if (n <= 0) {
                        cout << ui::YELLOW << "No IPs added.\n" << ui::RESET;
                        continue;
                    }
                    string line = "BLACKLIST,";
                    for (int i = 0; i < n; ++i) {
                        cout << ui::CYAN << "IP " << (i + 1) << ": " << ui::RESET;
                        string ip;
                        getline(cin, ip);
                        line += ip;
                        if (i + 1 != n) line += ";";
                    }
                    out << line << "\n";
                    cout << ui::GREEN << "Blacklist rule added.\n" << ui::RESET;

                } else {
                    cout << ui::RED << "Invalid choice.\n" << ui::RESET;
                }
            }
            out.close();

            try {
                la.loadRules("rules.txt");
                cout << ui::GREEN << "rules.txt created and loaded.\n" << ui::RESET;
            } catch (const exception &e) {
                cout << ui::RED << "Error loading rules: " << e.what() << ui::RESET << "\n";
            }
            ui::pause();
        }
        else if (c == 2) {
            cout << ui::YELLOW << "\n=== Rule Editor ===\n" << ui::RESET;

            ifstream rf("rules.txt");
            if (!rf) {
                cout << ui::YELLOW << "No rules.txt found. Use option 1 to create.\n" << ui::RESET;
            } else {
                cout << ui::BOLD << "\nCurrent rules:\n" << ui::RESET;
                cout << rf.rdbuf();
                rf.close();
            }

            cout << ui::CYAN << "\n1) Append new rule (raw text)\n"
                    "2) Clear all rules\n"
                    "3) Back\n" << ui::RESET;
            cout << ui::BOLD << "Choice: " << ui::RESET;
            int ec = readChoiceInt();

            if (ec == 1) {
                ofstream out("rules.txt", ios::app);
                if (!out) {
                    cout << ui::RED << "Cannot open rules.txt.\n" << ui::RESET;
                } else {
                    cout << ui::CYAN << "Append rule as text (e.g., THRESHOLD,LOGIN,FAILED,120,5):\n" << ui::RESET;
                    string line;
                    getline(cin, line);
                    out << line << "\n";
                    cout << ui::GREEN << "Rule appended.\n" << ui::RESET;
                }
            } else if (ec == 2) {
                ofstream out("rules.txt");
                out.close();
                cout << ui::GREEN << "All rules cleared (empty file).\n" << ui::RESET;
            }

            try {
                la.loadRules("rules.txt");
                cout << ui::GREEN << "Rules reloaded into analyzer.\n" << ui::RESET;
            } catch (const exception &e) {
                cout << ui::RED << "Error loading rules: " << e.what() << ui::RESET << "\n";
            }
            ui::pause();
        }
        else if (c == 3) {
            string savedPass;
            ifstream pf("report_pass.txt");
            if (pf) {
                getline(pf, savedPass);
                pf.close();
                cout << ui::CYAN << "Enter current report password (leave blank if you forgot): " << ui::RESET;
                string old;
                getline(cin, old);
                if (!savedPass.empty() && !old.empty() && old != savedPass) {
                    cout << ui::RED << "Current password incorrect. Cannot change.\n" << ui::RESET;
                    ui::pause();
                    continue;
                }
            } else {
                cout << ui::YELLOW << "No existing report password. A new one will be created.\n" << ui::RESET;
            }

            cout << ui::CYAN << "Enter new report password: " << ui::RESET;
            string newPass;
            getline(cin, newPass);

            ofstream pfOut("report_pass.txt");
            if (!pfOut) {
                cout << ui::RED << "Failed to write report_pass.txt\n" << ui::RESET;
            } else {
                pfOut << newPass;
                cout << ui::GREEN << "Report password changed.\n" << ui::RESET;
            }
            ui::pause();
        }
        else if (c == 4) {
            bool any = false;
            if (std::remove("incident_report.txt") == 0) {
                cout << ui::YELLOW << "Deleted incident_report.txt\n" << ui::RESET; any = true;
            }
            if (std::remove("incident_report.enc") == 0) {
                cout << ui::YELLOW << "Deleted incident_report.enc\n" << ui::RESET; any = true;
            }
            if (std::remove("report_pass.txt") == 0) {
                cout << ui::YELLOW << "Deleted report_pass.txt\n" << ui::RESET; any = true;
            }
            if (!any)
                cout << ui::YELLOW << "No report files to delete.\n" << ui::RESET;
            else
                cout << ui::GREEN << "Cleanup complete.\n" << ui::RESET;
            ui::pause();
        }
        else {
            cout << ui::RED << "Invalid choice.\n" << ui::RESET;
            ui::pause();
        }
    }
}

// ========== SECTION 5: UTILITIES & HELP ==========
void Admin::sectionUtilitiesHelp(LogAnalyzer &la) {
    for (;;) {
        ui::printHeader();
        cout << ui::GREEN << ui::BOLD << "=== 5. UTILITIES & HELP ===\n" << ui::RESET;
        cout << ui::CYAN << "1) " << ui::GREEN << "Show sample logs\n";
        cout << ui::CYAN << "2) " << ui::GREEN << "Security resources (web links)\n";
        cout << ui::CYAN << "3) " << ui::GREEN << "About this project\n";
        cout << ui::CYAN << "4) " << ui::RED   << "Back\n" << ui::RESET;
        cout << ui::BOLD << "Choice: " << ui::RESET;
        int c = readChoiceInt();
        if (c == 4) break;

        if (c == 1) {
            showLogsPreview(la);
            ui::pause();
        } else if (c == 2) {
            showResources();
            ui::pause();
        } else if (c == 3) {
            cout << ui::BOLD << "\n=== About CyberSentinel ===\n" << ui::RESET;
            cout << ui::CYAN
                    << "CyberSentinel is a console-based Intrusion Detection & Log Analysis System\n"
                       "implemented in C++ using Object Oriented Programming.\n\n"
                       "It demonstrates:\n"
                       " - OOP concepts (classes, inheritance, polymorphism, templates)\n"
                       " - Security log analysis (failed logins, blacklisted IPs)\n"
                       " - Incident reporting and basic risk scoring\n"
                       " - Simple encryption and password protection for reports\n"
                       " - Role-based access control (Admin / Analyst / Auditor)\n" << ui::RESET;
            ui::pause();
        } else {
            cout << ui::RED << "Invalid choice.\n" << ui::RESET;
            ui::pause();
        }
    }
}

// ===================== main =====================
int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    try {
        ensureKeyFile();
        ensureAccountsFile();
        ensureSampleFiles();

        vector<Account> accounts = loadAccounts();
        LogAnalyzer analyzer;

        try { analyzer.loadLogs("system_logs.txt"); }
        catch (...) { cerr << "[INFO] system_logs.txt not loaded (will use menu to create).\n"; }

        try { analyzer.loadRules("rules.txt"); }
        catch (...) { cerr << "[INFO] rules.txt not loaded (will use menu to create).\n"; }

        for (;;) {
            ui::printHeader();
            cout << ui::BOLD << ui::GREEN
                 << "Welcome to " << ui::RED << "CyberSentinel" << ui::GREEN
                 << " – Intrusion Detection & Log Analysis System\n" << ui::RESET;

            cout << "\n";
            cout << ui::CYAN << "1) " << ui::GREEN << "Select Role\n";
            cout << ui::CYAN << "2) " << ui::GREEN << "Settings (change passwords)\n";
            cout << ui::CYAN << "3) " << ui::RED   << "Exit\n" << ui::RESET;
            cout << ui::BOLD << "Choice: " << ui::RESET;
            int mainChoice = readIntLine();

            if (mainChoice == 3) {
                cout << ui::GREEN << "Exiting CyberSentinel. Goodbye!\n" << ui::RESET;
                break;
            }
            else if (mainChoice == 2) {
                runSettingsMenu(accounts);
                continue;
            }
            else if (mainChoice == 1) {
                ui::printHeader();
                cout << ui::BOLD << ui::CYAN << "Select Access Role:\n" << ui::RESET;
                cout << ui::CYAN << "1) " << ui::GREEN << "Security Admin   (full control)\n";
                cout << ui::CYAN << "2) " << ui::GREEN << "Security Analyst (analysis only)\n";
                cout << ui::CYAN << "3) " << ui::GREEN << "Security Auditor (view only)\n" << ui::RESET;
                cout << ui::BOLD << "Choice: " << ui::RESET;
                int roleChoice = readIntLine();

                Role r;
                if (roleChoice == 1) r = Role::ADMIN;
                else if (roleChoice == 2) r = Role::ANALYST;
                else if (roleChoice == 3) r = Role::AUDITOR;
                else {
                    cout << ui::RED << "Invalid role choice.\n" << ui::RESET;
                    ui::pause();
                    continue;
                }

                Admin admin(r);
                if (!admin.login(accounts)) {
                    ui::pause();
                    continue;
                }
                admin.menu(analyzer);
            }
            else {
                cout << ui::RED << "Invalid choice.\n" << ui::RESET;
                ui::pause();
            }
        }
    } catch (const exception &e) {
        cerr << ui::RED << "Fatal error: " << e.what() << ui::RESET << "\n";
        return 1;
    }
    return 0;
}
