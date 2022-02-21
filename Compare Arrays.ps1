  # Jämför en array med en annan som är "facit" och rätta till eventuella fel
# Rickard Warfvinge 2016-09-16
$Facit = @("server1", "server2", "server3", "server4", "server5")
$Lista = @("server1", "server9", "server13", "server4", "server5")
$AvvikandePositioner = Compare-Object -ReferenceObject $facit -DifferenceObject $lista -PassThru | where {$_. sideIndicator -eq "=>"}
 
Foreach ($Position in $AvvikandePositioner) {
 
# Sätter värdet från den korrekta positionen i $facit[] till $lista på rätt position
$Lista.SetValue( $Facit[$Lista .IndexOf($Position )], $Lista.IndexOf( $Position))
 
}
 
If (-Not (Compare-Object -ReferenceObject $Facit -DifferenceObject $Lista -PassThru) -eq "") {
 
# Något är fel. Arrayerna är inte identiska
 
}