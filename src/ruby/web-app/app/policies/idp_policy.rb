class IdpPolicy < ApplicationPolicy
    class Scope < Scope
      def resolve(permission = "backend_manage")
        if(user.superuser?)
          scope.all
        else
          scope.none
        end
      end
    end
  
    def show?
      can?("backend_manage")
    end
  
    def update?
      show?
    end
  
    def create?
      show?
    end
  
    def destroy?
      show?
    end
  
    private
  
    def can?(permission)
      allowed = false
      if(user.superuser?)
        allowed = true
      end

      allowed
    end
  end
  