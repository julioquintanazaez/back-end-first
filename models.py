from database import Base
import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Float, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from fastapi_utils.guid_type import GUID, GUID_DEFAULT_SQLITE
from sqlalchemy.types import TypeDecorator, String
import json

from uuid import UUID, uuid4  

class JSONEncodeDict(TypeDecorator):
	impl = String
	
	def process_bind_param(self, value, dialect):
		if value is not None:
			value = json.dumps(value)
		return value

	def process_result_value(self, value, dialect):
		if value is not None:
			value = json.loads(value)
		return value
		
class User(Base):
	__tablename__ = "user"
	
	username = Column(String(30), primary_key=True, unique=True, index=True) 
	full_name = Column(String(50), nullable=True, index=True) 
	email = Column(String(30), nullable=False, index=True) 
	#role = Column(String(15), nullable=False, index=True)#List[] #Scopes
	role = Column(JSONEncodeDict)
	disable = Column(Boolean, nullable=True, default=True)	
	hashed_password = Column(String(100), nullable=True, default=False)	

class Project(Base):  
	__tablename__ = "project"
	
	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	project_name = Column(String(50), unique=True, nullable=False, index=True)
	desc_proj = Column(String(100), nullable=True, default=None, index=True)
	inidate_proj = Column(DateTime, nullable=True, server_default=func.now())
	upddate_proj = Column(DateTime, onupdate=func.now()) 
	enddate_proj = Column(DateTime)
	manager = Column(String(50), nullable=False, index=True)
	mail_manager = Column(String(50), nullable=True)
	latitud = Column(Float, nullable=True, default=0.0) 	
	longitud = Column(Float, nullable=True, default=0.0) 
	is_active = Column(Boolean, nullable=True, default=True)
	#Relations with its child "Labor"
	labors = relationship("Labor", back_populates="project")
	
class Labor(Base): 
	__tablename__ = "labor"	
	
	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	type = Column(String(100), nullable=False, index=True)
	desc_labor = Column(String(100), nullable=True, default=None, index=True)
	inidate_labor = Column(DateTime, nullable=True, server_default=func.now())
	upddate_labor = Column(DateTime, onupdate=func.now()) 
	enddate_labor = Column(DateTime)	
	is_active = Column(Boolean, nullable=True, default=True)	
	#Relation with its father "Project"
	project_id = Column(GUID, ForeignKey("project.id"))
	project = relationship("Project", back_populates="labors")
	#Relations with its childs "Task, Equipment & Material"
	tasks = relationship("Task", back_populates="labor_tasks")
	equipments = relationship("Equipment", back_populates="labor_equipments")
	materials = relationship("Material", back_populates="labor_materials")
	
class Task(Base):
	__tablename__ = "task"

	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	description = Column(String(100), nullable=True, default=None, index=True) 
	mechanicals = Column(Integer, nullable=True, default=1)
	hour = Column(Integer, nullable=True, default=1)
	hour_men = Column(Integer, nullable=True, default=1)
	task_price = Column(Float, nullable=True, default=1.0)
	inidate_task = Column(DateTime, nullable=False, server_default=func.now())
	upddate_task = Column(DateTime, onupdate=func.now()) 
	enddate_task = Column(DateTime)	
	is_active = Column(Boolean, nullable=True, default=True)
	#Relation with its father "Labor"
	labor_task_id = Column(GUID, ForeignKey("labor.id"))	
	labor_tasks = relationship("Labor", back_populates="tasks")
	
class Equipment(Base):
	__tablename__ = "equipment"

	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	equipment_name = Column(String(100), nullable=True, default=None, index=True) 
	equipment_quantity = Column(Integer, nullable=True, default=1)
	equipment_unit_price = Column(Float, nullable=True, default=1.0)
	equipment_amount = Column(Float, nullable=True, default=1.0)
	#Relation with its father "Labor"
	labor_equipment_id = Column(GUID, ForeignKey("labor.id"))	
	labor_equipments = relationship("Labor", back_populates="equipments")

class Material(Base):  
	__tablename__ = 'material'
	
	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	material_name = Column(String(100), nullable=True, default=None, index=True) 
	material_type = Column(String(100), nullable=True, default=None, index=True) 
	material_quantity = Column(Integer, nullable=True, default=1)
	material_price = Column(Float, nullable=True, default=1.0) #es el mismo que el del material
	material_amount = Column(Float, nullable=True, default=1.0)	
	#Relation with its father "Labor"
	labor_material_id = Column(GUID, ForeignKey("labor.id"))	
	labor_materials = relationship("Labor", back_populates="materials")