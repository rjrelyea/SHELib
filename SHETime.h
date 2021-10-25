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

// helper class to format the time in a human usable way
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
#define MS_TO_S 1000.0
#define MS_TO_MIN (60.0*MS_TO_S)
#define MS_TO_H (60.0*MS_TO_MIN)
#define MS_TO_D (24*MS_TO_H)
  if (p.ptime < MS_TO_S) {
    str << p.ptime << "ms";
    return str;
  }
  if (p.ptime < MS_TO_MIN) {
    str << (p.ptime/MS_TO_S) << "s";
    return str;
  }
  if (p.ptime < MS_TO_H) {
    str << (p.ptime/MS_TO_MIN) << "min";
    return str;
  }
  if (p.ptime < (MS_TO_D)) {
    str << (p.ptime/MS_TO_H) << "h";
    return str;
  }
  str << (p.ptime/(MS_TO_D)) << "d";
  return str;
}
