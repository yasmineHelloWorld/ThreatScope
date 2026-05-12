import time
from collections import defaultdict, deque
from intelligence.detector.base import BaseDetector,DetectorResult

#class to detect number of attempts by changing user credentials per each try
#store IPs + count of attempts + timestamps of each login
#yehseb 3adad el mohawalat khelal akher x (Sliding Window)sanya law 3adet el threshold = attack


class BruteForceDetector(BaseDetector):

    def __init__(self,config:dict=None):
        config =config or {}
        self.window_seconds = config.get('window_seconds',60) #seconds if exists use it else ...
        self.threshold = config.get('threshold',10) #max number of attempts
        self.target_request_types = config.get('target_request_types',["POST"]) #list of request types to monitor
        self._attempts :dict[str,deque]=defaultdict(deque) #each ip has deque inside it timestamps of attempts
    @property
    def name(self)->str:
        return "brute_force"
    

    def detect(self,event_data:dict,history:list[dict])->DetectorResult:
        ip=event_data.get('ip_address',"") #default get has key and call back function
        request_type=event_data.get("request_type","")
        username=event_data.get("username")
        now=time.time()
        
        # Filter law method eli fel header law mkantsh POST we law mafish username fel request yeb2a ghaleban mesh login aslan
        if request_type not in self.target_request_types or not username:
            return DetectorResult(detector_name=self.name, score=0.0) #no need to process this event
        
        self._attempts[ip].append(now)
        self._cleanup(ip,now)

        attempts_count=len(self._attempts[ip])
        score= min(1.0,(attempts_count/self.threshold)) #3adad el mohawalat eli beyhawel feha ala threshold
        is_attack = attempts_count>=self.threshold
        
        return DetectorResult(
            detector_name=self.name,
            score=score,
            attack_type="brute_force" if is_attack else None,
            confidence=score,
            is_attack=is_attack,
            details={
                "attempts": attempts_count,
                "threshold": self.threshold,
                "window_seconds": self.window_seconds,
                "ip": ip
            }
        )

    # helper method to clean up the old timestamps to get only the current window
    def _cleanup(self, ip: str, now: float):
        window = self._attempts[ip]
        cutoff = now - self.window_seconds  # cutoff howa a2dam wa2t yb2a el mo7awala gowa el window
        while window and window[0] < cutoff:
            window.popleft()  # remove the oldest timestamp

    def reset(self):
        self._attempts.clear()  # clear the attempts




            
            


        
        

