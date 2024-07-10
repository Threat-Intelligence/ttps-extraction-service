# Use the official Python image from the Docker Hub
FROM python

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# Expose the port on which the Flask app will run
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=ioc_ttp_api.py

# Command to run the Flask app
CMD ["python", "ioc_ttp_api.py"]
