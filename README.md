Step 1: Build the Docker Image

Navigate to the directory containing the Dockerfile and test_data.py, and run:

    docker build -t test-data .

This will build the Docker image and tag it as test-data.

Step 2: Run the Docker Container

Once the image is built, you can run it using:

    docker run -it --name test-data-container test-data

This will start the container and execute the test_data.py script within the container.

Step 3: Verify the Results

After the script finishes running, check the logs generated inside the container by running:

    docker logs data-test-container

