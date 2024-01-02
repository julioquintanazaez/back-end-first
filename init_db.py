from sqlalchemy.orm import Session
import models
from database import SessionLocal, engine
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


models.Base.metadata.create_all(bind=engine)

		
def create_fake_data():

	db = SessionLocal()	
	db.drop_all()
	
	models.User.metadata.create(bind=engine)
	models.Project.metadata.create(bind=engine)
	models.Labor.metadata.create(bind=engine)
	models.Equipment.metadata.create(bind=engine)	
	models.Material.metadata.create(bind=engine)
	models.Task.metadata.create(bind=engine)
	
	db.create_all()
	db.commit()
	db.close()
	
	try:
		yield db
		
		user1 = models.User(
			username="julio",
			full_name="Julio Cesar Quintana Zaez",
			email="jupyterdevs2022@gmail.com",
			role="admin",
			is_activated=True,
			hashed_password=pwd_context.hash("admin987*!!+")	
		)
		user2 = models.User(
			username="cesar",
			full_name="Cesar Programador",
			email="jupyterdevs2022@gmail.com",
			role="maneger",
			is_activated=True,
			hashed_password=pwd_context.hash("maneger123*!!+")	
		)
		
		db.add_all([user1, user2])
		db.commit()
		
	finally:
		db.close()

	return "project created succefully"
	

	
if __name__ == "__main__":
    create_fake_data()



