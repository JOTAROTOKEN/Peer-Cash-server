FROM node:14
WORKDIR /src
COPY . /src
RUN npm install
ENV PORT 80
EXPOSE 80
CMD ["npm", "start"]