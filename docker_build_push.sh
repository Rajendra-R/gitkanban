echo $1 | docker login -u $2 --password-stdin
echo "started to build a docker image"
docker build -t deepcompute/gitkanban:gitkanban-$3 .
echo "successfully build the docker image"
echo "started pushing to docker hub"
docker push deepcompute/gitkanban:gitkanban-$3
echo "successfully pushed to docker hub"
