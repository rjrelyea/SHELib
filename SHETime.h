#include <chrono>
class Timer
{
private:
  std::chrono::time_point<std::chrono::system_clock> m_StartTime;
  std::chrono::time_point<std::chrono::system_clock> m_EndTime;
  bool m_bRunning = false;
public:
 void start(void) {
   m_StartTime = std::chrono::system_clock::now();
   m_bRunning = true;
 }
 void stop(void) {
   m_EndTime = std::chrono::system_clock::now();
   m_bRunning = false;
 }
 double elapsedMilliseconds(void) {
   std::chrono::time_point<std::chrono::system_clock> endTime;

   if (m_bRunning) {
     endTime = std::chrono::system_clock::now();
   } else {
     endTime = m_EndTime;
   }

   return std::chrono::duration_cast<std::chrono::milliseconds>
          (endTime-m_StartTime).count();
 }
 double elapsedSeconds(void) {
   return elapsedMilliseconds()/1000.0;
 }
};

class PrintTime
{
private:
  double ptime;
public:
  PrintTime(double t) : ptime(t) {}
  PrintTime(const PrintTime &p) : ptime(p.ptime)  {}
  friend std::ostream&operator<<(std::ostream&, const PrintTime &);
};

std::ostream&operator<<(std::ostream&str, const PrintTime &p) {
  if (p.ptime < 1000.0) {
    str << p.ptime << "ms";
    return str;
  }
  if (p.ptime < 60000.0) {
    str << (p.ptime/1000.0) << "s";
    return str;
  }
  if (p.ptime < 360000.0) {
    str << (p.ptime/60000.0) << "min";
    return str;
  }
  if (p.ptime < (360000.0*24.0)) {
    str << (p.ptime/360000.0) << "h";
    return str;
  }
  str << (p.ptime/(360000.0*24.0)) << "d";
  return str;
}
