"""Shared structural contracts. Evidence support still needs semantic checks."""
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator

class ContractModel(BaseModel):
    model_config=ConfigDict(extra='allow')

class ProgressContract(ContractModel):
    contract_version:Literal['1.0']
    job_id:str
    status:Literal['running','completed','failed']
    phase:str
    processed_bytes:int=Field(ge=0)
    total_bytes:int=Field(ge=0)
    records_read:int=Field(ge=0)
    records_parsed:int=Field(ge=0)
    malformed_records:int=Field(ge=0)
    error:dict|None

class Entity(ContractModel):
    entity_id:str
    type:Literal['host','account','ip']
    label:str

class Step(ContractModel):
    step_id:str
    step_index:int=Field(ge=1)
    timestamp:str
    summary:str
    rule_id:str
    technique_id:str|None
    tactic:str|None
    kill_chain_stage:str|None
    evidence_ids:list[str]=Field(min_length=1)
    primary_evidence_id:str
    evidence_strength:Literal['observed','derived','hypothesized']
    uncertainty_reason:str

class Edge(ContractModel):
    edge_id:str
    source_id:str|None=None
    target_id:str|None=None
    source_step_id:str|None=None
    target_step_id:str|None=None
    relationship:str
    evidence_ids:list[str]=Field(min_length=1)
    evidence_strength:Literal['observed','derived','hypothesized']
    @model_validator(mode='after')
    def endpoints(self):
        entity=bool(self.source_id and self.target_id)
        step=bool(self.source_step_id and self.target_step_id)
        if entity==step:raise ValueError('Edge requires exactly one pair of entity or step endpoints')
        return self

class IncidentContract(ContractModel):
    contract_version:Literal['1.0']
    incident_id:str
    job_id:str
    revision:int=Field(ge=1)
    incident_kind:Literal['single_finding','related_activity']
    title:str
    entities:list[Entity]
    steps:list[Step]
    edges:list[Edge]
    steps_truncated:bool
    total_step_count:int=Field(ge=0)
    ai_review:dict
