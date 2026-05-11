from abc import ABC, abstractmethod #imports mot3aleka bel abstract classes 
from dataclasses import dataclass,field
from typing import Optional #leha 3elaka bel type hinting 
#file dah howa el base detector le kol el detectors eli hayt3mlo ba3d keda zy XSS,SQLInjection ,

@dataclass #object eli hayrag3o kol detector 
class DetectorResult:
    detector_name:str
    score:float  #level el khotora
    attack_type:Optional[str] = None
    confidence:float=0.0 # ad eh el detector wasek men 
    is_attack:bool =False
    details:dict =field(default_factory=dict) # to make each object has it's own dict
    

class BaseDetector(ABC):
    @property # mean using the method as variable
    @abstractmethod #unique detector name used in scoring and logging 
    def name(self)->str:
        pass

    @abstractmethod
    def detect(self,event_data:dict,history:list[dict])->DetectorResult:
        pass

    # eventdata-> current event dict with keys ip addresses /servicetype/request type /username password/payload/endpoint/user agent/time(current request)
    #history->List of recent events dicts from the same ip 
    #returns  DetectorResult with score between 0-1 and metadata

    #optional if the detector need it in storing state
    def reset(self):
        pass
    
        