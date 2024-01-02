from typing import Union, Optional, List
from datetime import date
from pydantic import BaseModel, EmailStr 

class UserUPD(BaseModel):	
	username: str
	email: Union[str, None] = None
	full_name: Union[str, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class UserActivate(BaseModel):	
	disable: Union[bool, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
	
class User(BaseModel):	
	username: str
	email: Union[str, None] = None
	full_name: Union[str, None] = None
	role: Union[str, None] = None
	disable: Union[bool, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class UserInDB(User):
    hashed_password: str
	
class UserPassword(BaseModel):
    hashed_password: str
	
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
	username: Union[str, None] = None
	scopes: List[str] = []	
#-------------------------
#-------PROJECT-------------
#-------------------------
class Project(BaseModel):
	project_name : str
	desc_proj : str 
	manager : str
	mail_manager : EmailStr 
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class ProjectInDB(Project):
	id : str 
	inidate_proj : Union[date, None] = None
	upddate_proj : Union[date, None] = None
	enddate_proj : Union[date, None] = None
	latitud : Union[float, None] = None
	longitud : Union[float, None] = None
	is_active : Union[bool, None] = None 
#-------------------------
#-------LABOR-------------
#-------------------------	
class LaborActive(BaseModel):
	is_active: Union[bool, None] = None
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class LaborUPD(BaseModel):
	desc_labor : str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class Labor(BaseModel):
	type : str	
	desc_labor : str
	project_id: str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class LaborInDB(Labor):
	id: str		
	inidate_labor : date
	upddate_labor : date
	enddate_labor : date
	is_active : Union[bool, None] = None 

#-------------------------
#-------TASK-------------
#-------------------------
class TaskActive(BaseModel):
	is_active: Union[bool, None] = None
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
	
class TaskUPD(BaseModel):
	mechanicals : int
	hour : int
	task_price : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Task(BaseModel):
	description : str
	mechanicals : int
	hour : int
	task_price : float
	labor_task_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True		
		
class TaskInDB(Task):
	id: str
	hour_men : int
	inidate_task : date
	upddate_task : date
	enddate_task : date
	is_active : Union[bool, None] = None	
	
#-------------------------
#-------MATERIAL-------------
#-------------------------
class MaterialUPD(BaseModel):
	material_quantity : int
	material_price : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class Material(BaseModel):
	material_name: str
	material_type: str
	material_quantity : int
	material_price : float	
	labor_material_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class MaterialInDB(Material):
	id: str	
	material_amount : float
	
#-------------------------
#-------EQUIPMENT-------------
#-------------------------

class EquipmentUPD(BaseModel):
	equipment_quantity : int
	equipment_unit_price : float
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Equipment(BaseModel):
	equipment_name: str
	equipment_quantity : int
	equipment_unit_price : float
	labor_equipment_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class EquipmentInDB(Equipment):
	id: str
	equipment_amount : float	
	

#----------------------------------	
	
	
