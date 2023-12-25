from fastapi import Depends, FastAPI, HTTPException, status, Response, Security, Request
from functools import lru_cache
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import func
import models
import schemas
from database import SessionLocal, engine
from uuid import uuid4
from pathlib import Path
import init_db

from typing import Union
from datetime import datetime, timedelta

#---Imported for JWT example-----------
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
from typing_extensions import Annotated

import config 

#-------FAKE DB------------------------
#User: julio:admin987*!!+  / sherlock: backer356 / marco:marco123
#-------------------------------------
models.Base.metadata.create_all(bind=engine)



#Create resources for JWT flow
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(
	tokenUrl="token",
	scopes={"admin": "Add, edit and delete information.", "manager": "Create and read information.", "user": "Read information."}
)
#----------------------
#Create our main app
app = FastAPI()

#----SETUP MIDDLEWARES--------------------

# Allow these origins to access the API
origins = [
	"http://localhost",
	"https://localhost:3000",
	"https://tools.slingacademy.com",
	"https://www.slingacademy.com",
	"http://localhost.tiangolo.com",
	"https://localhost.tiangolo.com",
	"https://app-project-jczo.onrender.com",
	"http://app-project-jczo.onrender.com",	
	"http://localhost:8080",
	"https://localhost:8080",
	"http://localhost:5000",
	"https://localhost:5000",
	"http://localhost:3000",
	"https://localhost:3000",
	"http://localhost:8000",
	"https://localhost:8000",
]

# Allow these methods to be used
methods = ["GET", "POST", "PUT", "DELETE"]

# Only these headers are allowed
headers = ["Content-Type", "Authorization"]

app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=methods,
	allow_headers=headers,
	expose_headers=["*"]
)

ALGORITHM = config.ALGORITHM	
SECRET_KEY = config.SECRET_KEY
APP_NAME = config.APP_NAME
ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES

# Dependency
def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()


#------CODE FOR THE JWT EXAMPLE----------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
	db_user = db.query(models.User).filter(models.User.username == username).first()	
	if db_user is not None:
		return db_user 

#This function is used by "login_for_access_token"
def authenticate_user(username: str, password: str,  db: Session = Depends(get_db)):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password): #secret
        return False
    return user
	
#This function is used by "login_for_access_token"
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=5)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
	
#This function is used by "get currecnt active user" dependency security authentication
async def get_current_user(
			security_scopes: SecurityScopes, 
			token: Annotated[str, Depends(oauth2_scheme)],
			db: Session = Depends(get_db)):
	if security_scopes.scopes:
		authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
	else:
		authenticate_value = "Bearer"
		
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None:
			raise credentials_exception			
		token_scopes = payload.get("scopes", [])
		token_data = schemas.TokenData(scopes=token_scopes, username=username)
		
	except (JWTError, ValidationError):
		raise credentials_exception
			
		token_data = schemas.TokenData(username=username)
	except JWTError:
		raise credentials_exception
		
	user = get_user(db, username=token_data.username)
	if user is None:
		raise credentials_exception
		
	for user_scope in token_data.scopes:
		if user_scope not in security_scopes.scopes:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Not enough permissions",
				headers={"WWW-Authenticate": authenticate_value},
			)
			
	return user
	
async def get_current_active_user(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["admin", "manager", "user"])]):
	if current_user.disable:
		print({"USER AUTENTICATED" : current_user.disable})
		print({"USER ROLES" : current_user.role})
		raise HTTPException(status_code=400, detail="Inactive user")
	return current_user

#------------------------------------
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
	user = authenticate_user(form_data.username, form_data.password, db)
	if not user:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		)
	access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
	print(form_data.scopes)
	print(user.role)
	access_token = create_access_token(
		data={"sub": user.username, "scopes": [user.role]},   #form_data.scopes
		expires_delta=access_token_expires
	)
	return {"access_token": access_token, "token_type": "Bearer"}
	
#----This endpoint is to show how we can use the dependency injection for validated current user

@app.get("/")
def index():
	return {"Application": "Hello from developers"}
	
@app.get("/dumb/")
def dumb():
	#init_db.create_fake_data()
	return {"Conection": "Create Successfuly"}
	
	
@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin", "manager", "user"])]):
    return current_user
	
	
#######################
#Crud for PROJECTS here
#######################

@app.post("/create_project/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
def create_project(project: schemas.Project, db: Session = Depends(get_db)):	
	try:
		db_project = models.Project(
			name=project.name, 
			description=project.description,
			initial_date=func.now(),
			update_date = func.now(),
			manager=project.manager,
			mail_manager=project.mail_manager			
		)
		db.add(db_project)
		db.commit()
		db.refresh(db_project)	
		return db_project
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=500, detail="Unique integrity")

#Modificar la respuesta para que sea el error correcto, buscar diferentes tipos de errores
@app.get("/read_projects/", status_code=status.HTTP_201_CREATED)   #response_model=list[schemas.Item]
def read_projects(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	projects = db.query(models.Project).offset(skip).limit(limit).all()    
	return projects
	
@app.put("/update_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def update_project(project_id: str, project: schemas.Project, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == project_id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")
	#Values to be modified here, and the stored data recived the new values
	db_project.name = project.name
	db_project.description = project.description
	db_project.manager = project.manager
	db_project.mail_manager = project.mail_manager
	db_project.update_date = func.now()
	db.commit()
	db.refresh(db_project)	
	return db_project

@app.delete("/delete_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def delete_project(project_id: str, db: Session = Depends(get_db)):
	db_project = db.query(models.Project).filter(models.Project.id == project_id).first()
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found")	
	db.delete(db_project)	#delete the project from DB
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#####################
#Crud for LABORS here
#Many-to-Many remember
#####################

@app.post("/create_labor/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
def create_labor(labor: schemas.Labor, db: Session = Depends(get_db)):	
	try:
		db_labor = models.Labor(
			type=labor.type,		
			
		)
		db.add(db_labor) 
		db.commit()
		db.refresh(db_labor)	
		return db_labor
	except SQLAlchemyError as e: 
		raise HTTPException(status_code=500, detail="Unique integrity")
		
@app.get("/read_labors/", status_code=status.HTTP_201_CREATED)  
def read_labors(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	db_labors = db.query(models.Labor).offset(skip).limit(limit).all()    
	return db_labors

	
@app.put("/update_labor/{labor_id}", status_code=status.HTTP_201_CREATED) 
def update_labor(labor_id: str, upd_labor: schemas.Labor, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor category not found")
	db_labor.type=upd_labor.type
	db.commit()
	db.refresh(db_labor)	
	return db_labor

@app.delete("/delete_labor/{labor_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def delete_labor(labor_id: str, db: Session = Depends(get_db)):
	db_labor = db.query(models.Labor).filter(models.Labor.id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found")	
	db.delete(db_labor)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

					
#########################
###   USERS ADMIN  ######
#########################

@app.post("/create_user/", status_code=status.HTTP_201_CREATED)  
def create_user(user: schemas.UserInDB, db: Session = Depends(get_db)):
	if db.query(models.User).filter(models.User.username == user.username).first() :
		raise HTTPException( 
			status_code=400,
			detail="The user with this email already exists in the system",
		)	
	db_user = models.User(
		username=user.username, 
		full_name=user.full_name,
		email=user.email,
		role=user.role,
		disable=user.disable,
		hashed_password=pwd_context.hash(user.hashed_password)
	)
	db.add(db_user)
	db.commit()
	db.refresh(db_user)	
	return {f"User: {db_user.username}": "Succesfully created"}
	
@app.get("/read_users/", status_code=status.HTTP_201_CREATED)    #current_user: Annotated[schemas.User, Security(get_current_user, scopes=["admin"])]
def read_users(
		skip: int = 0, limit: int = 100,
		db: Session = Depends(get_db)
	):    	
	db_users = db.query(models.User).offset(skip).limit(limit).all()    
	return db_users

@app.put("/update_user/{username}", status_code=status.HTTP_201_CREATED) 
def update_user(username: str, new_user: schemas.UserUPD, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_user.username=new_user.username
	db_user.full_name=new_user.full_name
	db_user.email=new_user.email		
	db.commit()
	db.refresh(db_user)	
	return db_user	
	
@app.put("/activate_user/{username}", status_code=status.HTTP_201_CREATED) 
def activate_user(username: str, new_user: schemas.UserActivate, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_user.disable=new_user.disable		
	db.commit()
	db.refresh(db_user)	
	return db_user	
	
@app.delete("/delete_user/{username}", status_code=status.HTTP_201_CREATED) 
def delete_user(username: str, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db.delete(db_user)	
	db.commit()
	return {"Deleted": "Delete User Successfuly"}
	
@app.get("/read_user_by_username/{username}", status_code=status.HTTP_201_CREATED) 
def delete_user(username: str, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	return db_user
	
@app.put("/reset_password/{username}", status_code=status.HTTP_201_CREATED) 
def reset_password(username: str, password: schemas.UserPassword, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.username == username).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db_user.hashed_password=pwd_context.hash(password.hashed_password)
	db.commit()
	db.refresh(db_user)	
	return {"Result": "Password Updated Successfuly"}

#########################
#PL MATERial
##########################

@app.post("/create_pl_material/", status_code=status.HTTP_201_CREATED) 
def create_pl_material(pl_material: schemas.PL_Material, db: Session = Depends(get_db)):	
	db_labor = db.query(models.Labor).filter(models.Labor.id == pl_material.labor_id).first()	
	db_project = db.query(models.Project).filter(models.Project.id == pl_material.project_id).first()	
					  
	db_pl_material = models.PL_Material(	
		material=pl_material.material,  
		quantity=pl_material.quantity,	
		type_material=pl_material.type_material,
		price=pl_material.price,
		amount=(pl_material.quantity * pl_material.price),
		#Relations
		labor_id=db_labor.id,
		project_id=db_project.id,	 
	)
	db.add(db_pl_material) 
	db.commit()
	db.refresh(db_pl_material)
	return query

@app.get("/read_pl_materials/", status_code=status.HTTP_201_CREATED)  
def read_pl_materials(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_pl_laterials = db.query(models.PL_Material).offset(skip).limit(limit).all()    
	return db_pl_laterials
	
@app.get("/read_pl_materials_query/", status_code=status.HTTP_201_CREATED)  
def read_pl_materials_query(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	
	query = db.query(models.PL_Material.quantity,
					models.PL_Material.material,
					models.PL_Material.price,
					models.PL_Material.type_material,
					models.PL_Material.amount,
					models.PL_Material.id,
					models.PL_Material.labor_id,
					models.PL_Material.project_id,
					models.Labor.type,
					models.Project.name 
					  ).join(models.Labor, models.Project					  
					  ).filter(models.PL_Material.labor_id == models.Labor.id,
							models.PL_Material.project_id == models.Project.id
					  ).all()
	
	return query 
	
@app.get("/read_pl_material_by_project/{project_id}", status_code=status.HTTP_201_CREATED)  
def read_pl_material_by_project(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	query = db.query(models.PL_Material.labor_id, models.Labor.type
						).join(models.Labor, models.Labor.id == models.PL_Material.labor_id
						).group_by(models.PL_Material.labor_id
						).filter(models.PL_Material.project_id == project_id).all()
					  
	return query
	
@app.get("/read_pl_material_by_project_labor/{project_id, labor_id}", status_code=status.HTTP_201_CREATED)  
def read_pl_material_by_project_labor(project_id: str, labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	query = db.query(models.PL_Material.quantity,
					models.PL_Material.material,
					models.PL_Material.price,
					models.PL_Material.type_material,
					models.PL_Material.amount,
					models.PL_Material.id,
					models.PL_Material.labor_id,
					models.PL_Material.project_id,
					models.Labor.type,
					models.Project.name 
						).join(models.Labor, models.Project
						).filter(models.PL_Material.project_id == project_id, models.PL_Material.labor_id == labor_id 
						).all()
					  
	return query
	
@app.put("/update_pl_material/{id}", status_code=status.HTTP_201_CREATED) 
def update_pl_material(id: str, upd_labor_material: schemas.PL_MaterialUPD, db: Session = Depends(get_db)):
	db_pl_material = db.query(models.PL_Material).filter(models.PL_Material.id == id).first()
	if db_pl_material is None:
		raise HTTPException(status_code=404, detail="PL_Material not found")
	db_pl_material.quantity=upd_labor_material.quantity
	db_pl_material.price=upd_labor_material.price
	db_pl_material.amount=(upd_labor_material.quantity * upd_labor_material.price)
	db.commit()
	db.refresh(db_pl_material)	
	return db_pl_material	

@app.delete("/delete_pl_material/{id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def delete_pl_material(id: str, db: Session = Depends(get_db)):
	db_pl_material = db.query(models.PL_Material).filter(models.PL_Material.id == id).first()
	if db_pl_material is None:
		raise HTTPException(status_code=404, detail="PL_Material not found")	
	db.delete(db_pl_material)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#########################
#PL EQUIPMENT 
##############################

@app.post("/create_pl_equipment/", status_code=status.HTTP_201_CREATED) 
def create_pl_equipment(pl_equipment: schemas.PL_Equipment, db: Session = Depends(get_db)):	
	db_labor = db.query(models.Labor).filter(models.Labor.id == pl_equipment.labor_id).first()	
	db_project = db.query(models.Project).filter(models.Project.id == pl_equipment.project_id).first()	
					  
	db_pl_equipment = models.PL_Equipment(	
		equipment=pl_equipment.equipment,  
		quantity=pl_equipment.quantity,		
		unit_price=pl_equipment.unit_price,
		amount=(pl_equipment.quantity * pl_equipment.unit_price),
		#Relations
		labor_id=db_labor.id,
		project_id=db_project.id,	 
	)
	db.add(db_pl_equipment) 
	db.commit()
	db.refresh(db_pl_equipment)
	return db_pl_equipment

@app.get("/read_pl_equipments/", status_code=status.HTTP_201_CREATED)  
def read_pl_equipments(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_pl_equipments = db.query(models.PL_Equipment).offset(skip).limit(limit).all()    
	return db_pl_equipments
	
@app.get("/read_pl_equipments_query/", status_code=status.HTTP_201_CREATED)  
def read_pl_equipments_query(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	
	query = db.query(models.PL_Equipment.quantity,
					models.PL_Equipment.equipment,
					models.PL_Equipment.unit_price,
					models.PL_Equipment.amount,
					models.PL_Equipment.id,
					models.PL_Equipment.labor_id,
					models.PL_Equipment.project_id,
					models.Labor.type,
					models.Project.name 
					  ).join(models.Labor, models.Project					  
					  ).filter(models.PL_Equipment.labor_id == models.Labor.id,
							models.PL_Equipment.project_id == models.Project.id
					  ).all()
	
	return query 
	
@app.get("/read_pl_equipment_by_project/{project_id}", status_code=status.HTTP_201_CREATED)  
def read_pl_equipment_by_project(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	query = db.query(models.PL_Equipment.labor_id, models.Labor.type
						).join(models.Labor, models.Labor.id == models.PL_Equipment.labor_id
						).group_by(models.PL_Equipment.labor_id
						).filter(models.PL_Equipment.project_id == project_id).all()
					  
	return query
	
@app.get("/read_pl_equipment_by_project_labor/{project_id, labor_id}", status_code=status.HTTP_201_CREATED)  
def read_pl_equipment_by_project_labor(project_id: str, labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	query = db.query(models.PL_Equipment.quantity,
					models.PL_Equipment.equipment,
					models.PL_Equipment.unit_price,
					models.PL_Equipment.amount,
					models.PL_Equipment.id,
					models.PL_Equipment.labor_id,
					models.PL_Equipment.project_id,
					models.Labor.type,
					models.Project.name 
						).join(models.Labor, models.Project
						).filter(models.PL_Equipment.project_id == project_id, models.PL_Equipment.labor_id == labor_id 
						).all()
					  
	return query
	
@app.put("/update_pl_equipment/{id}", status_code=status.HTTP_201_CREATED) 
def update_pl_equipment(id: str, upd_equipment: schemas.PL_EquipmentUPD, db: Session = Depends(get_db)):
	db_pl_equipment = db.query(models.PL_Equipment).filter(models.PL_Equipment.id == id).first()
	if db_pl_equipment is None:
		raise HTTPException(status_code=404, detail="PL_Equipment not found")
	db_pl_equipment.quantity=upd_equipment.quantity
	db_pl_equipment.unit_price=upd_equipment.unit_price
	db_pl_equipment.amount=(upd_equipment.quantity * upd_equipment.unit_price)
	db.commit()
	db.refresh(db_pl_equipment)	
	return db_pl_equipment	

@app.delete("/delete_pl_equipment/{id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def delete_pl_equipment(id: str, db: Session = Depends(get_db)):
	db_pl_equipment = db.query(models.PL_Equipment).filter(models.PL_Equipment.id == id).first()
	if db_pl_equipment is None:
		raise HTTPException(status_code=404, detail="PL_Equipment not found")	
	db.delete(db_pl_equipment)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

#########################	
#PL TASK
#########################

@app.post("/create_pl_task/", status_code=status.HTTP_201_CREATED) 
def create_pl_task(pl_task: schemas.PL_Task, db: Session = Depends(get_db)):	
	db_labor = db.query(models.Labor).filter(models.Labor.id == pl_task.labor_id).first()	
	db_project = db.query(models.Project).filter(models.Project.id == pl_task.project_id).first()	
	
	db_pl_task = models.PL_Task(	
		description=pl_task.description,  
		mechanicals=pl_task.mechanicals,
		hour=pl_task.hour,
		hour_men=(pl_task.hour + pl_task.mechanicals),
		price=pl_task.price,
		#Relations
		labor_id=db_labor.id,
		project_id=db_project.id,	 
	)
	db.add(db_pl_task) 
	db.commit()
	db.refresh(db_pl_task)
	return db_pl_task

@app.get("/read_pl_task/", status_code=status.HTTP_201_CREATED)  
def read_pl_task(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	db_pl_tasks = db.query(models.PL_Task).offset(skip).limit(limit).all()    
	return db_pl_tasks
	
@app.get("/read_pl_tasks_query/", status_code=status.HTTP_201_CREATED)  
def read_pl_tasks_query(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	
	query = db.query(models.PL_Task.description,
					models.PL_Task.mechanicals,
					models.PL_Task.hour,
					models.PL_Task.hour_men,
					models.PL_Task.price,
					models.PL_Task.is_active,
					models.PL_Task.id,
					models.PL_Task.labor_id,
					models.PL_Task.project_id,
					models.Labor.type,
					models.Project.name 
					  ).join(models.Labor, models.Project					  
					  ).filter(models.PL_Task.labor_id == models.Labor.id,
							models.PL_Task.project_id == models.Project.id
					  ).all()
	
	return query 
	
@app.get("/read_pl_task_by_project/{project_id}", status_code=status.HTTP_201_CREATED)  
def read_pl_task_by_project(project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	query = db.query(models.PL_Task.labor_id, models.Labor.type
						).join(models.Labor, models.Labor.id == models.PL_Task.labor_id
						).group_by(models.PL_Task.labor_id
						).filter(models.PL_Task.project_id == project_id).all()
					  
	return query
	
@app.get("/read_pl_task_by_project_labor/{project_id, labor_id}", status_code=status.HTTP_201_CREATED)  
def read_pl_task_by_project_labor(project_id: str, labor_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	
	query = db.query(models.PL_Task.description,
					models.PL_Task.mechanicals,
					models.PL_Task.hour,
					models.PL_Task.hour_men,
					models.PL_Task.price,
					models.PL_Task.is_active,
					models.PL_Task.id,
					models.PL_Task.labor_id,
					models.PL_Task.project_id,
					models.Labor.type,
					models.Project.name 
						).join(models.Labor, models.Project
						).filter(models.PL_Task.project_id == project_id, models.PL_Task.labor_id == labor_id 
						).all()
					  
	return query

	
@app.put("/update_pl_task/{id}", status_code=status.HTTP_201_CREATED) 
def update_pl_task(id: str, upd_pl: schemas.PL_TaskUPD, db: Session = Depends(get_db)):
	db_pl_task = db.query(models.PL_Task).filter(models.PL_Task.id == id).first()
	if db_pl_task is None:
		raise HTTPException(status_code=404, detail="PL_Task not found")
	db_pl_task.mechanicals=upd_pl.mechanicals
	db_pl_task.hour=upd_pl.hour
	db_pl_task.price=upd_pl.price
	db_pl_task.hour_men=(upd_pl.hour *	upd_pl.mechanicals)
	db.commit()
	db.refresh(db_pl_task)	
	return db_pl_task	

@app.delete("/delete_pl_task/{id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
def delete_pl_task(id: str, db: Session = Depends(get_db)):
	db_pl_task = db.query(models.PL_Task).filter(PL_Task).first()
	if db_pl_task is None:
		raise HTTPException(status_code=404, detail="PL_Task not found")	
	db.delete(db_pl_task)	
	db.commit()
	return {"Deleted": "Delete Successfuly"}

@app.put("/activate_pl_task/{id}", status_code=status.HTTP_201_CREATED) 
def activate_pl_task(id: str, task: schemas.PL_TaskActive, db: Session = Depends(get_db)):
	db_task = db.query(models.PL_Task).filter(models.PL_Task.id == id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_task.is_active=task.is_active;		
	db.commit()
	db.refresh(db_task)	
	return {"Task": "Successfully changed"}	
	

##################################
###   STATISTICS for TASK ########
##################################

@app.get("/summay_project_labors_task/{project_id}", status_code=status.HTTP_201_CREATED)  
def summay_project_labors_task(project_id: str, db: Session = Depends(get_db)):  
	
	labors = db.query(
					models.Labor.type, 
					func.sum(models.PL_Task.price).label('total_amount'), 
					func.sum(models.PL_Task.hour_men).label('total_hour_men'), 
					func.count(models.PL_Task.id).label('labor_count'),
					func.sum(models.PL_Task.mechanicals).label('labor_mechanicals'),
					).join(models.Labor
					).join(models.Project, models.Project.id == models.PL_Task.project_id
					).group_by(models.PL_Task.labor_id).filter(models.PL_Task.project_id == project_id).all() 
					
	return labors
	
@app.get("/list_project_labor_tasks/{project_id}", status_code=status.HTTP_201_CREATED)  
def list_project_labor_tasks(project_id: str, db: Session = Depends(get_db)):  
	
	labors = db.query(
						models.Labor.type,
						models.PL_Task.description,
						models.PL_Task.mechanicals,
						models.PL_Task.hour_men,
						models.PL_Task.price,						
					).filter(
						models.PL_Task.labor_id == models.Labor.id,
						models.PL_Task.project_id==project_id).order_by(models.Labor.type).all()

	return labors

#######################################
###   STATISTICS for EQUIPMENT ########
#######################################

@app.get("/summay_project_labors_equipment/{project_id}", status_code=status.HTTP_201_CREATED)  
def summay_project_labors_equipment(project_id: str, db: Session = Depends(get_db)):  
	
	equipment = db.query(
					models.Labor.type, 
					func.sum(models.PL_Equipment.amount).label('total_amount'), 
					func.sum(models.PL_Equipment.quantity).label('total_quantity'), 
					func.count(models.PL_Equipment.id).label('equipment_count'),
					).join(models.Labor
					).join(models.Project, models.Project.id == models.PL_Equipment.project_id
					).group_by(models.PL_Equipment.labor_id).filter(models.PL_Equipment.project_id == project_id).all()
					
	return equipment
	
@app.get("/list_project_labor_equipment/{project_id}", status_code=status.HTTP_201_CREATED)  
def list_project_labor_equipment(project_id: str, db: Session = Depends(get_db)):  
	
	equipment = db.query(
						models.Labor.type,
						models.PL_Equipment.equipment,
						models.PL_Equipment.quantity,
						models.PL_Equipment.unit_price,
						models.PL_Equipment.amount,					
					).filter(
						models.PL_Equipment.labor_id == models.Labor.id,
						models.PL_Equipment.project_id==project_id).order_by(models.Labor.type).all()

	return equipment


#######################################
###   STATISTICS for MATERIALS ########
#######################################

@app.get("/summay_project_labors_material/{project_id}", status_code=status.HTTP_201_CREATED)  
def summay_project_labors_material(project_id: str, db: Session = Depends(get_db)):  
	
	material = db.query(
					models.Labor.type, models.PL_Material.type_material,
					func.sum(models.PL_Material.amount).label('total_amount'), 
					func.sum(models.PL_Material.quantity).label('total_quantity'), 
					func.count(models.PL_Material.type_material).label('type_count'),
					func.count(models.PL_Material.id).label('material_count'),
					).join(models.Labor
					).join(models.Project, models.Project.id == models.PL_Material.project_id
					).group_by(models.PL_Material.labor_id
					).group_by(models.PL_Material.type_material
					).filter(models.PL_Material.project_id == project_id).all()
					
	return material
	
@app.get("/list_project_labor_material/{project_id}", status_code=status.HTTP_201_CREATED)  
def list_project_labor_material(project_id: str, db: Session = Depends(get_db)):  
	
	material = db.query(
						models.Labor.type,
						models.PL_Material.material,
						models.PL_Material.quantity,
						models.PL_Material.type_material,
						models.PL_Material.amount,					
					).filter(
						models.PL_Material.labor_id == models.Labor.id,
						models.PL_Material.project_id==project_id).order_by(models.Labor.type).all()

	return material