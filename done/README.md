README projet ESSONNI Ali et BEN RAHHAL Yasmin

Nous sommes arrivé dans notre projet à la dernière semaine (semaine 13)
Nous avons pu finir et faire fonctionner tous les tests du latest jusqu'au week 13 où
1 test sur 3 fail.
Ce test est en rapport avec une valeur qui doit être set et get par la suite et qui crée un 
leak dans le server lorsqu'on run le make feedback, ou une undefined behavior (des fois fonctionne des fois non)
lorsqu'on le run sur notre machine.
Ce problème vient d'un leak du côté du serveur que le make feedback arrive à détécter, cependant nous n'arrivons pas à retrouver ce leak lorsqu'on debug sur notre machine.
Nous soupçonnons que ce leak est lié a un certain curl_free(key) que l'on devrait appeler dans ckvs_httpd, cependant on ne sait pas trop où l'appeler car lorsqu'on le fait,
on nous sort encore plus de messages d'erreur.
Neanmoins, comme dit plus haut, ces tests fonctionnent en local.